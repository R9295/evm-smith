use alloy_primitives::{Address, keccak256};
use anyhow::{Context as _, Result, anyhow, bail};
use clap::Parser;
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Write as _},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime},
};

use crate::{
    addresses::ExecutionAddresses,
    machine::{Config, DEFAULT_MEMORY_LENGTH_LIMIT, DEFAULT_MEMORY_OFFSET_LIMIT, Machine},
    opcodes::Opcode,
};

/// Standard EEST test sender private key. Address: 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b.
const DEFAULT_SENDER_SK: [u8; 32] = [
    0x45, 0xa9, 0x15, 0xe4, 0xd0, 0x60, 0x14, 0x9e, 0xb4, 0x36, 0x59, 0x60, 0xe6, 0xa7, 0xa4, 0x5f,
    0x33, 0x43, 0x93, 0x09, 0x30, 0x61, 0x11, 0x6b, 0x19, 0x7e, 0x32, 0x40, 0x06, 0x5f, 0xf2, 0xd8,
];

const FORK: &str = "Osaka";
const DEFAULT_CLIENT_TIMEOUT_SECS: u64 = 10;
const POLL_INTERVAL: Duration = Duration::from_micros(100);

#[derive(Parser, Debug, Clone)]
#[command(
    about = "Cross-client state-test fuzzer driving geth, nethermind, and besu in shared-memory server mode."
)]
pub struct Cli {
    #[arg(long)]
    pub geth_path: PathBuf,
    #[arg(long)]
    pub nethermind_path: PathBuf,
    #[arg(long)]
    pub besu_path: PathBuf,
    /// Number of iterations to run. 0 means run forever.
    #[arg(long, default_value_t = 0)]
    pub count: u64,
    /// RNG seed. Default: time-based.
    #[arg(long)]
    pub seed: Option<u64>,
    /// Generator gas budget per iteration.
    #[arg(long, default_value_t = 3_000_000)]
    pub gas: u32,
    /// Number of parallel worker triplets to run.
    #[arg(long, default_value_t = 1)]
    pub cores: usize,
    /// Per-client timeout per iteration, in seconds.
    #[arg(long, default_value_t = DEFAULT_CLIENT_TIMEOUT_SECS)]
    pub timeout: u64,
    /// Exit non-zero on the first FAIL or root mismatch.
    #[arg(long, default_value_t = false)]
    pub bail: bool,
    /// Inclusive max memory offset sampled by generated memory-touching opcodes.
    #[arg(long, default_value_t = DEFAULT_MEMORY_OFFSET_LIMIT)]
    pub memory_offset_limit: u64,
    /// Inclusive max memory length sampled by generated memory-touching opcodes.
    #[arg(long, default_value_t = DEFAULT_MEMORY_LENGTH_LIMIT)]
    pub memory_length_limit: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientKind {
    Geth,
    Nethermind,
    Besu,
}

impl ClientKind {
    fn name(self) -> &'static str {
        match self {
            ClientKind::Geth => "geth",
            ClientKind::Nethermind => "nethermind",
            ClientKind::Besu => "besu",
        }
    }
}

struct ClientServer {
    kind: ClientKind,
    binary_path: PathBuf,
    workdir: PathBuf,
    data_path: PathBuf,
    signal_path: PathBuf,
    child: Child,
}

impl ClientServer {
    fn spawn(binary: &Path, kind: ClientKind, workdir: &Path) -> Result<Self> {
        let (data_path, signal_path, child) = Self::start_child(binary, kind, workdir)?;
        Ok(Self {
            kind,
            binary_path: binary.to_path_buf(),
            workdir: workdir.to_path_buf(),
            data_path,
            signal_path,
            child,
        })
    }

    fn start_child(
        binary: &Path,
        kind: ClientKind,
        workdir: &Path,
    ) -> Result<(PathBuf, PathBuf, Child)> {
        let data_path = workdir.join(format!("{}.json", kind.name()));
        let signal_path = workdir.join(format!("{}.json.signal", kind.name()));
        // Clear any stale signal so the child won't race-trigger on whatever is left over.
        let _ = fs::remove_file(&signal_path);
        let _ = fs::remove_file(&data_path);

        let log_path = workdir.join(format!("{}.log", kind.name()));
        let log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .with_context(|| format!("opening {}", log_path.display()))?;
        let log_file2 = log_file.try_clone()?;

        let mut cmd = Command::new(binary);
        match kind {
            ClientKind::Geth => {
                cmd.args(["statetest", "--statetest.shared-memory"])
                    .arg(&data_path);
            }
            ClientKind::Nethermind => {
                cmd.args(["--shared-memory-file"]).arg(&data_path);
            }
            ClientKind::Besu => {
                cmd.args(["state-test", "--shared-memory-file"])
                    .arg(&data_path);
            }
        }
        cmd.stdout(Stdio::from(log_file))
            .stderr(Stdio::from(log_file2));
        let child = cmd
            .spawn()
            .with_context(|| format!("spawning {} ({})", kind.name(), binary.display()))?;

        Ok((data_path, signal_path, child))
    }

    fn kill_child(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn stop_child(&mut self) {
        // Best-effort: tell the server to exit cleanly. If it's already dead, kill it.
        let _ = atomic_write(&self.signal_path, b"EXIT");
        let exited = wait_with_timeout(&mut self.child, Duration::from_secs(2));
        if !exited {
            self.kill_child();
        }
    }

    fn restart(&mut self) -> Result<()> {
        self.kill_child();
        let (data_path, signal_path, child) =
            Self::start_child(&self.binary_path, self.kind, &self.workdir)?;
        self.data_path = data_path;
        self.signal_path = signal_path;
        self.child = child;
        Ok(())
    }

    fn read_signal(&self) -> String {
        fs::read_to_string(&self.signal_path)
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    }

    fn read_data(&self) -> Result<String> {
        Ok(fs::read_to_string(&self.data_path)?.trim().to_string())
    }
}

impl Drop for ClientServer {
    fn drop(&mut self) {
        self.stop_child();
    }
}

fn wait_with_timeout(child: &mut Child, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) => {
                if Instant::now() >= deadline {
                    return false;
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => return false,
        }
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension(format!(
        "{}.tmp",
        path.extension().and_then(|s| s.to_str()).unwrap_or("")
    ));
    {
        let mut f = File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(bytes)?;
        f.sync_data().ok();
    }
    fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

fn scratch_base_dir() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/tmp")
    } else {
        PathBuf::from("/dev/shm")
    }
}

fn create_core_workdir(core_id: usize) -> Result<PathBuf> {
    let base = scratch_base_dir();
    let path = base.join(format!("evm-fuzz-core-{core_id}"));
    match fs::remove_dir_all(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("removing workdir {}", path.display())),
    }
    fs::create_dir(&path).with_context(|| format!("creating workdir {}", path.display()))?;
    Ok(path)
}

fn derive_sender(sk: &[u8; 32]) -> Result<Address> {
    let secp = secp256k1::Secp256k1::new();
    let secret = secp256k1::SecretKey::from_byte_array(sk)
        .map_err(|e| anyhow!("invalid sender secret key: {e}"))?;
    let pk = secp256k1::PublicKey::from_secret_key(&secp, &secret);
    let serialized = pk.serialize_uncompressed();
    // serialize_uncompressed returns 65 bytes: leading 0x04 tag + 64 bytes of x||y.
    let hash = keccak256(&serialized[1..]);
    Ok(Address::from_slice(&hash[12..]))
}

fn hex0x(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn build_state_test_json(
    bytecode: &[u8],
    sender: Address,
    sender_sk: &[u8; 32],
    _gas: u32,
) -> Value {
    let gas_limit = 167_77_216u32;
    json!({
        "evm-fuzz": {
            "env": {
                "currentCoinbase": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
                "currentDifficulty": "0x020000",
                "currentRandom": "0x0000000000000000000000000000000000000000000000000000000000020000",
                "currentGasLimit": "0xffffffffffffff",
                "currentNumber": "0x01",
                "currentTimestamp": "0x03e8",
                "currentBaseFee": "0x0a",
                "currentExcessBlobGas": "0x00",
                "previousHash": "0x5e20a0453cecd065ea59c37ac63e079ee08998b6045136a8ce6635c7912ec0b6",
            },
            "pre": {
                hex0x(sender.as_slice()): {
                    // 1 ETH + u128::MAX, matching runner.rs:88.
                    "balance": "0x1000000000000000000ffffffffffffffff",
                    "code": "0x",
                    "nonce": "0x00",
                    "storage": {},
                },
                "0x4242424242424242424242424242424242424242": {
                    "balance": "0x00",
                    "code": hex0x(bytecode),
                    "nonce": "0x01",
                    "storage": {},
                },
            },
            "transaction": {
                "data": ["0x"],
                "gasLimit": [format!("{:#x}", gas_limit)],
                "gasPrice": "0x0a",
                "nonce": "0x00",
                "secretKey": hex0x(sender_sk),
                "to": "0x4242424242424242424242424242424242424242",
                "value": ["0xde0b6b3a7640000"],
            },
            "post": {
                FORK: [{
                    "hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "logs": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "indexes": {"data": 0, "gas": 0, "value": 0},
                }]
            },
        }
    })
}

fn write_bug_testcase(workdir: &Path, bytecode: &[u8], ctx: &WorkerContext) -> Result<PathBuf> {
    let json_val = build_state_test_json(bytecode, ctx.sender, &ctx.sender_sk, ctx.cli.gas);
    let json_bytes = serde_json::to_vec_pretty(&json_val)?;
    let path = workdir.join("bug.json");
    atomic_write(&path, &json_bytes)?;
    Ok(path)
}

#[derive(Debug)]
struct OkResult {
    state_root: String,
    logs_hash: String,
    stack_witness: String,
}

#[derive(Debug)]
enum ClientResult {
    Ok(OkResult),
    Fail(String),
}

struct RunOneOutput {
    results: [ClientResult; 3],
    output: String,
}

struct SharedState {
    next_iter: AtomicU64,
    completed: AtomicU64,
    mismatches: AtomicU64,
    fails: AtomicU64,
    stop: AtomicBool,
    print_lock: Mutex<()>,
}

impl SharedState {
    fn new() -> Self {
        Self {
            next_iter: AtomicU64::new(0),
            completed: AtomicU64::new(0),
            mismatches: AtomicU64::new(0),
            fails: AtomicU64::new(0),
            stop: AtomicBool::new(false),
            print_lock: Mutex::new(()),
        }
    }
}

#[derive(Clone)]
struct WorkerContext {
    id: usize,
    cli: Cli,
    seed: u64,
    sender: Address,
    sender_sk: [u8; 32],
    config: Config,
    shared: Arc<SharedState>,
}

fn parse_ok_payload(payload: &str) -> OkResult {
    let mut lines = payload.lines();
    let state_root = lines.next().unwrap_or("").trim().to_string();
    let logs_hash = lines.next().unwrap_or("").trim().to_string();
    let stack_witness = lines.next().unwrap_or("[]").trim().to_string();
    OkResult {
        state_root,
        logs_hash,
        stack_witness,
    }
}

fn failure_summary(err: &str) -> String {
    err.lines().next().unwrap_or("").chars().take(200).collect()
}

fn pairwise_disagreements(servers: &[ClientServer; 3], results: &[ClientResult; 3]) -> Vec<String> {
    let mut disagreements = Vec::new();
    for i in 0..results.len() {
        for j in (i + 1)..results.len() {
            let left_name = servers[i].kind.name();
            let right_name = servers[j].kind.name();
            match (&results[i], &results[j]) {
                (ClientResult::Ok(left), ClientResult::Ok(right)) => {
                    let mut dimensions = Vec::with_capacity(3);
                    if left.state_root != right.state_root {
                        dimensions.push("STATE ROOT");
                    }
                    if left.logs_hash != right.logs_hash {
                        dimensions.push("LOGS HASH");
                    }
                    if left.stack_witness != right.stack_witness {
                        dimensions.push("STACK");
                    }
                    if !dimensions.is_empty() {
                        disagreements.push(format!(
                            "{left_name} != {right_name} on {}",
                            dimensions.join(", ")
                        ));
                    }
                }
                (ClientResult::Fail(left_err), ClientResult::Fail(right_err)) => {
                    let left_summary = failure_summary(left_err);
                    let right_summary = failure_summary(right_err);
                    if left_summary != right_summary {
                        disagreements
                            .push(format!("{left_name} != {right_name} on FAILURE REASON"));
                    }
                }
                (ClientResult::Ok(_), ClientResult::Fail(_))
                | (ClientResult::Fail(_), ClientResult::Ok(_)) => {
                    disagreements.push(format!(
                        "{left_name} != {right_name} on STATUS (OK vs FAIL)"
                    ));
                }
            }
        }
    }
    disagreements
}

fn append_differing_stacks(
    output: &mut String,
    servers: &[ClientServer; 3],
    results: &[ClientResult; 3],
) {
    let mut groups: Vec<(String, Vec<&'static str>)> = Vec::new();
    for (server, result) in servers.iter().zip(results.iter()) {
        let ClientResult::Ok(ok) = result else {
            continue;
        };
        if let Some((_, names)) = groups
            .iter_mut()
            .find(|(stack_witness, _)| *stack_witness == ok.stack_witness)
        {
            names.push(server.kind.name());
        } else {
            groups.push((ok.stack_witness.clone(), vec![server.kind.name()]));
        }
    }

    if groups.len() <= 1 {
        return;
    }

    output.push_str("  differing stacks:\n");
    for (stack_witness, names) in groups {
        output.push_str(&format!("    [{}]: {}\n", names.join(", "), stack_witness));
    }
}

fn run_one(
    servers: &mut [ClientServer; 3],
    bytecode: &[u8],
    sender: Address,
    sender_sk: &[u8; 32],
    gas: u32,
    timeout: Duration,
    _worker_id: usize,
    _iter: u64,
) -> Result<RunOneOutput> {
    let json_val = build_state_test_json(bytecode, sender, sender_sk, gas);
    let json_bytes = serde_json::to_vec(&json_val)?;

    for srv in servers.iter() {
        atomic_write(&srv.data_path, &json_bytes)
            .with_context(|| format!("writing test for {}", srv.kind.name()))?;
    }
    let mut deadlines = [Instant::now(); 3];
    for (i, srv) in servers.iter().enumerate() {
        atomic_write(&srv.signal_path, b"START")
            .with_context(|| format!("writing START for {}", srv.kind.name()))?;
        deadlines[i] = Instant::now() + timeout;
    }

    let mut done: [Option<ClientResult>; 3] = [None, None, None];
    let output = String::new();
    loop {
        let mut all_done = true;
        for (i, srv) in servers.iter_mut().enumerate() {
            if done[i].is_some() {
                continue;
            }
            // Detect crashed children.
            if let Ok(Some(status)) = srv.child.try_wait() {
                let name = srv.kind.name();
                done[i] = Some(ClientResult::Fail(format!(
                    "{name} server exited prematurely with {status}"
                )));
                srv.restart()
                    .with_context(|| format!("restarting {name} after premature exit"))?;
                continue;
            }
            match srv.read_signal().as_str() {
                "OK" => match srv.read_data() {
                    Ok(payload) => done[i] = Some(ClientResult::Ok(parse_ok_payload(&payload))),
                    Err(e) => {
                        done[i] = Some(ClientResult::Fail(format!("(failed to read result: {e})")))
                    }
                },
                "FAIL" => {
                    let err = srv
                        .read_data()
                        .unwrap_or_else(|e| format!("(failed to read error: {e})"));
                    done[i] = Some(ClientResult::Fail(err));
                }
                _ => {
                    if Instant::now() >= deadlines[i] {
                        let name = srv.kind.name();
                        done[i] = Some(ClientResult::Fail(format!(
                            "{name} timed out after {} seconds",
                            timeout.as_secs()
                        )));
                        srv.restart()
                            .with_context(|| format!("restarting {name} after timeout"))?;
                    } else {
                        all_done = false;
                    }
                }
            }
        }
        if all_done {
            break;
        }
        thread::sleep(POLL_INTERVAL);
    }

    Ok(RunOneOutput {
        results: done.map(|o| o.expect("all_done loop guarantees Some")),
        output,
    })
}

fn generate_bytecode(iter: u64, seed: u64, gas: u32, config: &Config) -> Vec<u8> {
    let machine_seed = seed.wrapping_add(iter);
    let mut machine = Machine::new(
        gas as u64,
        fastrand::Rng::with_seed(machine_seed),
        config.clone(),
    );
    let mut rand = fastrand::Rng::with_seed(machine_seed);
    loop {
        let op = Opcode::generate_with_memory_limits(
            &mut rand,
            config.memory_offset_limit,
            config.memory_length_limit,
        );
        if machine.ingest(op).is_err() {
            break;
        }
    }
    machine.bytecode()
}

fn print_locked(shared: &SharedState, output: &str) {
    let _guard = shared.print_lock.lock().expect("print lock poisoned");
    print!("{output}");
}

fn run_iteration(ctx: &WorkerContext, servers: &mut [ClientServer; 3], iter: u64) -> Result<()> {
    let machine_seed = ctx.seed.wrapping_add(iter);
    let bytecode = generate_bytecode(iter, ctx.seed, ctx.cli.gas, &ctx.config);
    let timeout = Duration::from_secs(ctx.cli.timeout);

    let RunOneOutput {
        results,
        mut output,
    } = run_one(
        servers,
        &bytecode,
        ctx.sender,
        &ctx.sender_sk,
        ctx.cli.gas,
        timeout,
        ctx.id,
        iter,
    )?;
    ctx.shared.completed.fetch_add(1, Ordering::Relaxed);

    let mut oks: Vec<&OkResult> = Vec::with_capacity(3);
    let mut any_fail = false;
    for r in results.iter() {
        match r {
            ClientResult::Ok(ok) => oks.push(ok),
            ClientResult::Fail(_) => any_fail = true,
        }
    }

    let mut printed = false;
    if any_fail {
        ctx.shared.fails.fetch_add(1, Ordering::Relaxed);
        let bug_path = write_bug_testcase(&servers[0].workdir, &bytecode, ctx)?;
        output.push_str(&format!(
            "worker {} iter {iter} (seed {machine_seed}): FAIL\n",
            ctx.id
        ));
        for (i, r) in results.iter().enumerate() {
            let name = servers[i].kind.name();
            match r {
                ClientResult::Ok(ok) => {
                    output.push_str(&format!(
                        "  {name}: OK state={} logs={}\n",
                        ok.state_root, ok.logs_hash
                    ));
                }
                ClientResult::Fail(err) => {
                    let one_line = failure_summary(err);
                    output.push_str(&format!("  {name}: FAIL {one_line}\n"));
                }
            }
        }
        for disagreement in pairwise_disagreements(servers, &results) {
            output.push_str(&format!("  disagree: {disagreement}\n"));
        }
        append_differing_stacks(&mut output, servers, &results);
        output.push_str(&format!("  testcase: {}\n", bug_path.display()));
        output.push_str(&format!("  bytecode: {}\n", hex0x(&bytecode)));
        print_locked(&ctx.shared, &output);
        printed = true;
        if ctx.cli.bail {
            ctx.shared.stop.store(true, Ordering::SeqCst);
            bail!("--bail: exiting on FAIL at iter {iter}");
        }
    } else {
        let first = oks[0];
        let state_match = oks.iter().all(|o| o.state_root == first.state_root);
        let logs_match = oks.iter().all(|o| o.logs_hash == first.logs_hash);
        let stack_match = oks.iter().all(|o| o.stack_witness == first.stack_witness);
        if state_match && logs_match && stack_match {
            if iter % 100 == 0 {
                output.push_str(&format!(
                    "worker {} iter {iter} (seed {machine_seed}): OK state={} logs={}\n",
                    ctx.id, first.state_root, first.logs_hash
                ));
            }
        } else {
            ctx.shared.mismatches.fetch_add(1, Ordering::Relaxed);
            let bug_path = write_bug_testcase(&servers[0].workdir, &bytecode, ctx)?;
            let mut mismatched_dimensions = Vec::with_capacity(3);
            if !state_match {
                mismatched_dimensions.push("STATE ROOT");
            }
            if !logs_match {
                mismatched_dimensions.push("LOGS HASH");
            }
            if !stack_match {
                mismatched_dimensions.push("STACK");
            }
            let kind = format!("{} MISMATCH", mismatched_dimensions.join("+"));
            output.push_str(&format!(
                "worker {} iter {iter} (seed {machine_seed}): {kind}\n",
                ctx.id
            ));
            for (i, ok) in oks.iter().enumerate() {
                output.push_str(&format!(
                    "  {}: state={} logs={}\n",
                    servers[i].kind.name(),
                    ok.state_root,
                    ok.logs_hash
                ));
            }
            for disagreement in pairwise_disagreements(servers, &results) {
                output.push_str(&format!("  disagree: {disagreement}\n"));
            }
            append_differing_stacks(&mut output, servers, &results);
            output.push_str(&format!("  testcase: {}\n", bug_path.display()));
            output.push_str(&format!("  bytecode: {}\n", hex0x(&bytecode)));
            print_locked(&ctx.shared, &output);
            printed = true;
            if ctx.cli.bail {
                ctx.shared.stop.store(true, Ordering::SeqCst);
                bail!("--bail: exiting on {kind} at iter {iter}");
            }
        }
    }

    if !printed && !output.is_empty() {
        print_locked(&ctx.shared, &output);
    }

    Ok(())
}

fn run_worker(ctx: WorkerContext) -> Result<()> {
    let workdir = create_core_workdir(ctx.id)?;
    print_locked(
        &ctx.shared,
        &format!("worker {} workdir: {}\n", ctx.id, workdir.display()),
    );

    let mut servers: [ClientServer; 3] = [
        ClientServer::spawn(&ctx.cli.geth_path, ClientKind::Geth, &workdir)?,
        ClientServer::spawn(&ctx.cli.nethermind_path, ClientKind::Nethermind, &workdir)?,
        ClientServer::spawn(&ctx.cli.besu_path, ClientKind::Besu, &workdir)?,
    ];

    loop {
        if ctx.shared.stop.load(Ordering::SeqCst) {
            break;
        }

        let iter = ctx.shared.next_iter.fetch_add(1, Ordering::Relaxed);
        if ctx.cli.count > 0 && iter >= ctx.cli.count {
            break;
        }

        run_iteration(&ctx, &mut servers, iter)?;
    }

    Ok(())
}

pub fn run(cli: Cli) -> Result<()> {
    if cli.cores == 0 {
        bail!("--cores must be greater than 0");
    }
    if cli.timeout == 0 {
        bail!("--timeout must be greater than 0");
    }

    let sender_sk = DEFAULT_SENDER_SK;
    let sender = derive_sender(&sender_sk)?;
    println!("sender address: {}", hex0x(sender.as_slice()));

    let mut config = Config::default();
    config.addresses = ExecutionAddresses {
        caller: sender,
        contract: ExecutionAddresses::default().contract,
    };
    config.memory_offset_limit = cli.memory_offset_limit;
    config.memory_length_limit = cli.memory_length_limit;
    config.addresses.assert_valid();

    let seed = cli.seed.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    });
    println!("seed: {seed}");
    println!("cores: {}", cli.cores);
    println!("timeout: {}s", cli.timeout);
    println!("memory offset limit: {}", config.memory_offset_limit);
    println!("memory length limit: {}", config.memory_length_limit);

    let shared = Arc::new(SharedState::new());
    let mut handles = Vec::with_capacity(cli.cores);
    for id in 0..cli.cores {
        let ctx = WorkerContext {
            id,
            cli: cli.clone(),
            seed,
            sender,
            sender_sk,
            config: config.clone(),
            shared: Arc::clone(&shared),
        };
        let shared_for_error = Arc::clone(&shared);
        handles.push(thread::spawn(move || {
            let result = run_worker(ctx);
            if result.is_err() {
                shared_for_error.stop.store(true, Ordering::SeqCst);
            }
            result
        }));
    }

    let mut first_error = None;
    for handle in handles {
        match handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
            Err(_) => {
                if first_error.is_none() {
                    first_error = Some(anyhow!("worker thread panicked"));
                }
            }
        }
    }

    let iter = shared.completed.load(Ordering::Relaxed);
    let mismatches = shared.mismatches.load(Ordering::Relaxed);
    let fails = shared.fails.load(Ordering::Relaxed);
    println!("done: {iter} iterations, {mismatches} root mismatches, {fails} fails");

    if let Some(e) = first_error {
        Err(e)
    } else {
        Ok(())
    }
}
