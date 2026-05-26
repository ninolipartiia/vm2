# `CallframeInterface::read_contract_code` is an unchecked slice index

- **Severity:** LOW (tracer-side host panic; reachable any time a tracer
  passes a slot beyond the current code page length)
- **Category:** liveness / undocumented panic in public tracer API
- **Confidence:** 9/10
- **Status:** open

## Summary

`read_contract_code` indexes `code_page()` directly with no bounds check,
while the `slot` argument is a `u16` (`0..=65_535`). For a normal contract
whose code page has `N` words, any `slot >= N` panics the host. The empty
code page installed by `Program::new_panicking()` after a failed `far_call`
is the most extreme case — every slot panics there — but the same shape
applies to every frame.

## Affected code

[`crates/vm2/src/tracing.rs:245-247`](../crates/vm2/src/tracing.rs#L245-L247):

```rust
fn read_contract_code(&self, slot: u16) -> U256 {
    self.frame.program.code_page()[slot as usize]
}
```

`slot: u16` ranges `0..=65_535`; `code_page()` for a normal contract is
much shorter than that, and is `vec![]` entirely for the
`Program::new_panicking()` frame installed at
[`far_call.rs:132`](../crates/vm2/src/instruction_handlers/far_call.rs#L132)
when a `far_call` cannot begin (no code at target, OOG on
`pay_for_decommit`, malformed `code_info`).

## Why the signature is misleading

The trait declaration ([`vm2-interface/src/state_interface.rs:151-152`](../crates/vm2-interface/src/state_interface.rs#L151-L152))
is:

```rust
/// Reads a word from the bytecode of the executing contract.
fn read_contract_code(&self, slot: u16) -> U256;
```

No `# Panics` note, no `Option`/`Result` return. A neighbouring accessor —
`program_counter` (line 99) — already returns `Option<u16>` and documents
the panic-frame case, establishing the precedent that frame-dependent
absence is expressed through the return type rather than as a host-side
panic. Against that precedent, the totalising `u16 → U256` signature here
is the outlier, and an embedder reading the trait would reasonably assume
the call is total.


## Why severity is LOW

Embedder-conditional: the panic only fires if an embedder calls this
accessor with a slot past the end of the current code page. This reads more
like a dangerous-API shape than a concrete bug — the trait advertises a
total `u16 → U256` read with no panic warning, so any future tracer
written against the trait could fall into it.

## Fix

Bounds-check at the accessor:

```rust
fn read_contract_code(&self, slot: u16) -> U256 {
    self.frame
        .program
        .code_page()
        .get(slot as usize)
        .copied()
        .unwrap_or_default()
}
```

