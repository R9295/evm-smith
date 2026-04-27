# Limitations

## Sub-machines cannot CALL contracts they themselves deploy

In `Machine`, the `callable_addresses` set governs which addresses an
`Opcode::Call` can target. The root machine grows it on every CREATE / CREATE2,
so root-level CALL ops can target any contract the root deployed.

Sub-machines (built by `build_generated_submachine` for a CREATE / CREATE2
init code) inherit a snapshot of the parent's `callable_addresses` and run
with `Config::grow_callable_on_create = false`. They can call:

- the root caller (`0x11..11`)
- any contract the root deployed *before* the sub-machine was constructed
- any contract any *ancestor* deployed before the current branch

They CANNOT call contracts they deploy themselves.

### Why

CREATE2's address is `keccak256(0xff ++ creator ++ salt ++ keccak256(init_code))`,
so we need `init_code` before we can compute the address. To work around the
chicken-and-egg with the sub-machine's `current_address`, `build_create2_init_code`
runs two passes:

1. **Probe** — build the sub-machine with `current_address = Address::ZERO`,
   render `probe_code`, derive `created_address = create2_from_code(creator,
   salt, probe_code)`.
2. **Final** — rebuild with `current_address = created_address`, render
   `final_code`. Used as the actual init code in the outer's bytecode.

The scheme only works under the invariant `probe_code == final_code` (asserted
by `debug_assert_eq!` in `build_create2_init_code`). If the rendered bytes
ever depend on `current_address`, the probe-derived address won't match what
the runtime computes from `final_code`, and the symbolic / runtime created
addresses diverge.

A nested CREATE inside a sub-machine appends `create_address(sub.current_address,
nonce)` to `callable_addresses`. That address differs between probe and final
because `current_address` does. A subsequent CALL that picks the appended
entry bakes 20 differing bytes into the rendered bytecode via PUSH20, breaking
the invariant.

`grow_callable_on_create = false` in sub-machines blocks the leak by skipping
the append. CREATE-only sub-machines (no CREATE2 anywhere in the ancestor chain)
*could* in principle grow safely, but the flag is set unconditionally for all
sub-machines because the propagation is simpler and the lost variety is small
(sub-machines still have ancestors' deployments to target).

### Tests

`src/machine.rs::tests`:

- `nested_create_taints_callable_when_grow_on_create_is_true` — concrete demonstration of the leak.
- `nested_create_leaves_callable_alone_when_grow_on_create_is_false` — the production setting blocks it.

### Possible future relaxation

Allowing CREATE sub-machines (those with no CREATE2 ancestor) to grow callable
would require propagating a `is_under_create2` flag through the sub-machine
chain and only forcing `grow_callable_on_create = false` when that flag is
set. The current code does not distinguish, so the restriction applies to
every sub-machine regardless of the parent's CREATE vs CREATE2 status.
