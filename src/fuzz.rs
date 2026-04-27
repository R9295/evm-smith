use alloy_primitives::{keccak256, Address};
use anyhow::{anyhow, bail, Context as _, Result};
use clap::Parser;
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Write as _},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime},
};

use crate::{
    addresses::ExecutionAddresses,
    machine::{Config, Machine},
    opcodes::Opcode,
};

/// Standard EEST test sender private key. Address: 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b.
const DEFAULT_SENDER_SK: [u8; 32] = [
    0x45, 0xa9, 0x15, 0xe4, 0xd0, 0x60, 0x14, 0x9e, 0xb4, 0x36, 0x59, 0x60, 0xe6, 0xa7, 0xa4, 0x5f,
    0x33, 0x43, 0x93, 0x09, 0x30, 0x61, 0x11, 0x6b, 0x19, 0x7e, 0x32, 0x40, 0x06, 0x5f, 0xf2, 0xd8,
];

const FORK: &str = "Osaka";
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_micros(100);

#[derive(Parser, Debug)]
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
    /// Exit non-zero on the first FAIL or root mismatch.
    #[arg(long, default_value_t = false)]
    pub bail: bool,
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

fn create_random_workdir() -> Result<PathBuf> {
    let base = scratch_base_dir();
    for _ in 0..100 {
        let path = base.join(format!("evm-fuzz-{:016x}", fastrand::u64(..)));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(e).with_context(|| format!("creating workdir {}", path.display()));
            }
        }
    }
    bail!("failed to create a unique workdir in {}", base.display())
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

#[derive(Debug)]
struct OkResult {
    state_root: String,
    logs_hash: String,
}

#[derive(Debug)]
enum ClientResult {
    Ok(OkResult),
    Fail(String),
}

fn parse_ok_payload(payload: &str) -> OkResult {
    let mut lines = payload.lines();
    let state_root = lines.next().unwrap_or("").trim().to_string();
    let logs_hash = lines.next().unwrap_or("").trim().to_string();
    OkResult {
        state_root,
        logs_hash,
    }
}

fn run_one(
    servers: &mut [ClientServer; 3],
    bytecode: &[u8],
    sender: Address,
    sender_sk: &[u8; 32],
    gas: u32,
) -> Result<[ClientResult; 3]> {
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
        deadlines[i] = Instant::now() + CLIENT_TIMEOUT;
    }

    let mut done: [Option<ClientResult>; 3] = [None, None, None];
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
                    Ok(payload) => {
                        println!("{}\n{}", srv.kind.name(), payload);
                        done[i] = Some(ClientResult::Ok(parse_ok_payload(&payload)))
                    }
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
                            CLIENT_TIMEOUT.as_secs()
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

    Ok(done.map(|o| o.expect("all_done loop guarantees Some")))
}

pub fn run(cli: Cli) -> Result<()> {
    let workdir = create_random_workdir()?;
    println!("workdir: {}", workdir.display());

    let sender_sk = DEFAULT_SENDER_SK;
    let sender = derive_sender(&sender_sk)?;
    println!("sender address: {}", hex0x(sender.as_slice()));

    let mut config = Config::default();
    config.addresses = ExecutionAddresses {
        caller: sender,
        contract: ExecutionAddresses::default().contract,
    };
    config.addresses.assert_valid();

    let seed = cli.seed.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    });
    println!("seed: {seed}");

    let mut servers: [ClientServer; 3] = [
        ClientServer::spawn(&cli.geth_path, ClientKind::Geth, &workdir)?,
        ClientServer::spawn(&cli.nethermind_path, ClientKind::Nethermind, &workdir)?,
        ClientServer::spawn(&cli.besu_path, ClientKind::Besu, &workdir)?,
    ];

    let mut iter: u64 = 0;
    let mut mismatches: u64 = 0;
    let mut fails: u64 = 0;
    loop {
        if cli.count > 0 && iter >= cli.count {
            break;
        }

        let machine_seed = seed.wrapping_add(iter);
        let mut machine = Machine::new(
            cli.gas as u64,
            fastrand::Rng::with_seed(machine_seed),
            config.clone(),
        );
        let mut rand = fastrand::Rng::with_seed(machine_seed);
        loop {
            let op = Opcode::generate(&mut rand);
            if machine.ingest(op).is_err() {
                break;
            }
        }
        let bytecode = machine.bytecode();

        let results = run_one(&mut servers, &bytecode, sender, &sender_sk, cli.gas)?;

        let mut oks: Vec<&OkResult> = Vec::with_capacity(3);
        let mut any_fail = false;
        for r in results.iter() {
            match r {
                ClientResult::Ok(ok) => oks.push(ok),
                ClientResult::Fail(_) => any_fail = true,
            }
        }

        if any_fail {
            fails += 1;
            println!("iter {iter} (seed {machine_seed}): FAIL");
            for (i, r) in results.iter().enumerate() {
                let name = servers[i].kind.name();
                match r {
                    ClientResult::Ok(ok) => {
                        println!("  {name}: OK state={} logs={}", ok.state_root, ok.logs_hash)
                    }
                    ClientResult::Fail(err) => {
                        let one_line: String =
                            err.lines().next().unwrap_or("").chars().take(200).collect();
                        println!("  {name}: FAIL {one_line}");
                    }
                }
            }
            println!("  bytecode: {}", hex0x(&bytecode));
            if cli.bail {
                bail!("--bail: exiting on FAIL at iter {iter}");
            }
        } else {
            let first = oks[0];
            let state_match = oks.iter().all(|o| o.state_root == first.state_root);
            let logs_match = oks.iter().all(|o| o.logs_hash == first.logs_hash);
            if state_match && logs_match {
                if iter % 100 == 0 {
                    println!(
                        "iter {iter} (seed {machine_seed}): OK state={} logs={}",
                        first.state_root, first.logs_hash
                    );
                }
            } else {
                mismatches += 1;
                let kind = if !state_match && !logs_match {
                    "STATE+LOGS MISMATCH"
                } else if !state_match {
                    "STATE ROOT MISMATCH"
                } else {
                    "LOGS HASH MISMATCH"
                };
                println!("iter {iter} (seed {machine_seed}): {kind}");
                for (i, ok) in oks.iter().enumerate() {
                    println!(
                        "  {}: state={} logs={}",
                        servers[i].kind.name(),
                        ok.state_root,
                        ok.logs_hash
                    );
                }
                println!("  bytecode: {}", hex0x(&bytecode));
                if cli.bail {
                    bail!("--bail: exiting on {kind} at iter {iter}");
                }
            }
        }

        iter += 1;
    }

    println!("done: {iter} iterations, {mismatches} root mismatches, {fails} fails");
    Ok(())
}
