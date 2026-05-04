---
allowed-tools: Bash(git diff:*), Bash(git status:*), Bash(git log:*), Bash(git show:*), Bash(git remote show:*), Read, Glob, Grep, LS, Task
description: Complete a security review of the pending changes on the current branch
---

You are a senior security engineer conducting a focused security review of this codebase.

GIT STATUS:

```
!`git status`
```

FILES MODIFIED:

```
!`git diff --name-only origin/HEAD...`
```

COMMITS:

```
!`git log --no-decorate origin/HEAD...`
```

DIFF CONTENT:

```
!`git diff --merge-base origin/HEAD`
```

Review the complete diff above. This contains all code changes in the PR. This can give some hint and ideas of the changes implemented in this PR. However, the focus should not be solely on the PR, but on the whole codebase.


OBJECTIVE:
Perform a security-focused code review to identify security vulnerabilities that could have real exploitation potential.

CRITICAL INSTRUCTIONS:
1. MINIMIZE FALSE POSITIVES: Only flag issues where you're >50% confident of actual exploitability
2. AVOID NOISE: Skip theoretical issues, style concerns, or low-impact findings
3. FOCUS ON IMPACT: Prioritize vulnerabilities that could lead to unauthorized access, data breaches, system compromise, or vm2 vs zk_evm divergencies
4. EXCLUSIONS: Do NOT report the following issue types:
   - NONE, report all kinds of findings

SECURITY CATEGORIES TO EXAMINE:

**Consensus Divergence with zk_evm (Proven Path):**
- Different state-transition output between vm2 (sequencer) and zk_evm (prover) on identical input — the canonical correctness boundary
- Frame-stipend / gas / pubdata mismatches at instruction-step granularity (cf. evm-stipend-divergence, id:000000–id:000003)
- Snapshot/rollback paths that leave state which zk_evm would not reach (cf. decommit-rollback-leak)
- "Used-contract-hashes" / DecommitState::Unsuccessful legacy-compat output drift
- Differences in storage-log queries, event ordering, L2-to-L1 logs, refund counters

**Panic / Assert Reachability (Sequencer DoS):**
- assert!s in heap.rs (allocate_at, deallocate, decode, allocate_with_content_at "page is already allocated")
- unwrap_or_else(|| panic!(...)) in heap operations
- INVALID_INSTRUCTION_COST = u32::MAX trick correctness on every reachable code path
- Frame-stack-overflow assumption (VM_MAX_STACK_DEPTH ≥ 214_748_444 static check, no per-call increment in common.rs)
- expect("calldata length overflow"), expect("Too many storage logs"), expect("bytecode length overflow") on attacker-influenced inputs
- RotateLeft/RotateRight (a << shift) | (a >> (256 − shift)) (binop.rs:130,140) with shift = b.low_u32() % 256: at shift == 0, the right operand is >> 256, which primitive_types::U256 panics on — reachable from any bytecode with b ≡ 0 (mod 256)
- Panics inside tracer hooks — interpreter is not panic-safe (raw pc)

**unsafe Code Memory Safety:**
- Raw pc: *const Instruction<T,W> dispatch in vm.rs:84, common.rs:48,71 — outliving the backing Arc<[Instruction]>
- FatPointer ↔ u128 transmute (fat_pointer.rs:23,30,38) — little-endian-only, layout-load-bearing repr(C)
- Box::from_raw(alloc_zeroed(...)) for the 64KB stack and the manual Clone (stack.rs:24,99-108)
- get_unchecked on state.registers() and register_pointer_flags (addressing_modes.rs:486,495,502) relies on the n < 16 check in Register::new. The decoder feeds parsed.src0_reg_idx / dst0_reg_idx into Register::new without bounds-checking the upstream output (decode.rs:53,69,84,85); verify zkevm_opcode_defs actually constrains those to 0..16 for every parsed opcode
- 'static sentinel Instructions (PANIC/INVALID/jump_to_beginning) outside any Program
- Predicate enum transmute soundness (addressing_modes.rs:158) — assumes every Arguments.predicate_and_mode_requirements was written by Arguments::new(Predicate, …). Arguments fields are private; verify no path constructs Arguments with raw bytes
- Send/Sync auto-derive interaction with the raw pc

**FatPointer and Heap Aliasing Invariants:**
- Upward calldata-pointer rule on Ret (ret.rs:48-58) and the kernel-mode bypass
- pointer.memory_page != current_frame.calldata_heap invariant
- register_pointer_flags bit-per-register accuracy under move/clobber paths
- Pointer-flag handling on stack writes and on system-call register preservation (r3..r12 keep value, all flags reset to "only r1 is a pointer")
- erase_fat_pointer_metadata non-kernel erasure for pointer_op second operand
- PointerAdd/Sub/Pack/Shrink overflow / length underflow checks
- FatPointer::narrow() start += offset is unchecked u32 arithmetic (far_call.rs:283-287); the only precondition checked at the call site is offset <= length. Adversarially-chosen start near u32::MAX (forwarded pointer from kernel return / precompile output) overflows silently

**Snapshot, Rollback, and Reentrant State Integrity:**
- External vs internal snapshot tier separation; make_snapshot only valid in bootloader frame; single-snapshot invariant
- Destructive RollbackableMap/Set/Log/Pod: rollback can be performed at most once, and ordering matters
- decommit_pinned_pages un-pinning during external_rollback vs state.heaps.dynamic sweep coverage (cf. known leak)
- transient_storage_changes clear on IncrementTxNumber interplay with snapshot revert
- append_rollback_logs correctness for failed near/far frames
- heaps_i_am_keeping_alive accounting on rollback and pop_frame
- next_base_page restoration vs orphaned dynamic page slots
- Bootloader word-level rollback log only triggered for writes via Heaps::write_u256/write_bytes to HeapId::FIRST and FIRST_AUX; verify no other mutation path bypasses record_bootloader_word_rollback for those pages

**Decommit and Bytecode Loading:**
- code_info_bytes[0] (version) decoding — 0x01 native, 0x02 EVM blob, default-AA fallback
- code_info_bytes[1] parity with zk_evm — vm2 returns None (panicking new frame) on code_info_bytes[1] ∉ {0,1} (decommit.rs:79-85); verify zk_evm produces an identical effect for the same byte, since AccountCodeStorage[address] can in principle be anything
- is_evm vs is_evm_blob_format split (post-evm-stipend-divergence fix)
- materialize_decommit_page keep-alive-vs-pin asymmetry when candidate equals current_frame.heap/aux_heap
- pay_for_decommit OOG path that records DecommitState::Unsuccessful without burning gas
- decommit_opcode extra-cost refund-on-cached and is_valid_format validation
- Kernel-address aliasing rule for default-AA selection (is_kernel(address))

**Call Frame Setup (Far / Near / Delegate / Mimic):**
- Address derivation per calling mode: Delegate (preserves address/caller/context_u128), Mimic (reads from r15), Normal
- r3..r12 pointer-flag clearing on system call vs full register zero on non-system call
- call_type byte (is_static_call_to_evm_interpreter << 2 | is_system_call << 1 | is_constructor_call)
- shard_id != 0 panicking branch with mandatory calldata construction (heap-resize side effect)
- mandated_gas flow when caller can't afford it (gas zeroed, panic frame)
- New-frame heap_size/aux_heap_size stipend selection (is_kernel/is_evm_blob_format/userspace)

**Privilege Mode / Static Context Enforcement:**
- mode_requirements().met(is_kernel, is_static) gate uniformly applied via boilerplate
- is_constructor_call masking (abi.is_constructor_call && current_frame.is_kernel)
- is_system_call gating on kernel destination (is_kernel(destination_address))
- Static-call propagation through new_frame_is_static && !is_evm_interpreter
- Side-effects-in-static-context routed through free_panic
- Privileged-opcode reachability outside system calls

**Gas / Ergs Accounting Errors:**
- 63/64 rule integer-order (gas / 64 - 63 vs gas - 63 / 64) and starvation edge cases in far_call.rs
- Mandated-gas burn-on-shortfall semantics for MsgValueSimulator
- Static cost charged before predicate / mode check (common.rs:60-69)
- Decommit-OOG that does not burn gas (legacy quirk) and Unsuccessful recording for shadow-mode parity
- Heap-growth pricing (1 erg/byte, checked_sub semantics, frame-local heap_size/aux_heap_size)
- Storage refund constants and assertions (refund <= SLOAD_COST/SSTORE_COST)
- Near-call gas pass with gas_to_pass == 0 ("pass everything") and leftover-refund on failure
- WorldDiff.pubdata: i32 saturation — driven by attacker-controlled cost_of_writing_storage deltas (storage path) and caller-supplied extra_pubdata_cost (precompile path, precompiles.rs:87). Either can drive pubdata.0 past i32::MAX/MIN with debug-mode panic / release-mode wrap. No saturating arithmetic in either site

**Decoder and Bytecode Pipeline:**
- decode.rs opcode dispatch: every variant constructed with the right monomorphize! specialization
- Reserved gas-cost tags 1–4 collision protection (encode_static_gas_cost panic)
- End-of-program marker: from_invalid() vs jump_to_beginning for exactly-1<<16-instruction programs (16-bit PC overflow)
- Predicate / mode-requirements bit-packing in predicate_and_mode_requirements
- Untrusted bytecode reaching Program::new from World::decommit — assumption that worlds return well-formed Programs
- Arguments 8-byte layout invariant for cache density

**Arithmetic, Operand, and Flag Handling:**
- Shift/rotate modulo-256 masking semantics (and the >> 256 panic noted under Sequencer DoS above)
- Div by zero returning (0, 0) with overflow flag
- Mul flag derivation from high.is_zero() / low.is_zero()
- Add/Sub overflowing_* propagation into Flags(LT, EQ, GT)
- Stack addressing wrapping (u16 arithmetic via wrapping_add/wrapping_sub) — verify intentional
- RelativeStack/AdvanceStackPointer SP-mutating side effects on read

**Heap Allocation and Page-ID Arithmetic:**
- HeapId decode (Static / BootloaderCalldata / BootloaderHeap / BootloaderAuxHeap / Dynamic{group, kind})
- allocate_with_content_at panic on already-allocated slot — sequencer-killer
- record_bootloader_range_rollback start.checked_add(len) overflow path
- read_u256_partially semantics on out-of-range reads (zero-extension)
- next_base_page monotonic invariant as the basis for the upward-pointer rule

**Storage, Pubdata, and Refund Accounting:**
- Cold/warm slot tracking via RollbackableSet (rollback to pre-VM-run only) and refund derivation
- paid_changes "prepaid vs new" pubdata delta (update_cost − prepaid)
- is_free_storage_slot short-circuit and WARM_WRITE_REFUND correctness
- read_storage_without_refund (far-call decommit-time read) parity with legacy
- transient_storage_changes non-rollback on IncrementTxNumber
- LogQuery.timestamp uniqueness vs zk_evm real timestamps (witness-incompatible by design)
- cost_of_writing_storage adversarial-World consequences

**Precompile Dispatch and System-Contract Trust:**
- Caller-supplied extra_ergs_cost / extra_pubdata_cost accepted as ground truth ("safe because system contracts are trusted")
- memory_page == 0 sentinel rebinding to current heap
- Output truncation by min(output.len, abi.output_memory_length) — partial writes
- address_low 16-bit address dispatch and unknown-address fallthrough behavior in LegacyPrecompiles
- PrecompileMemoryReader::next "assumes the offset never overflows"
- aux_input (u64) opaque routing to precompile

**EVM Emulator (0x02 Blob) Compatibility Surface:**
- Construction-state 0x02 masking divergence from zk_evm (the four AFL crashes)
- EVM-stipend NEW_EVM_FRAME_MEMORY_STIPEND = 57344 vs userspace 4096
- is_evm_interpreter interaction with is_static (static-call-to-EVM bit in r2)
- Code-version mismatch with construction phase (ContractDeployer._constructEVMContract 0x0201… sentinel)
- evm_interpreter_code_hash is supplied by the embedder via Settings; misconfigured/wrong hash routes EVM calls through unintended bytecode

**vm2-interface Tracer ABI Stability:**
- Frozen-trait promise: tracer compiled against version N works against any ≥ N
- forall_simple_opcodes! / OpcodeType extension model
- Tuple composition (A, B) and () no-op tracer
- VmAndWorld reborrow lifetime correctness during before_instruction / after_instruction
- Tracer panics during dispatch — soundness around pc advancement
- on_extra_prover_cycles truthfulness for prover-cycle accounting

**World Trait Embedder Trust Boundary:**
- Adversarial World::decommit returning malformed Program
- World::cost_of_writing_storage returning wildly inconsistent values across calls
- is_free_storage_slot non-determinism breaking refund invariants
- World::precompiles() returning custom Precompiles with wrong output length / cycle stats
- read_storage returning different values between calls in the same VM run
Event / L2-to-L1 Log and Output Stream Integrity:
- event_writer address gating (event.rs:18) — divergence from zk_evm's broader kernel-context emission is a known accepted gap
- Log ordering and rollback truncation across snapshots
- is_first / is_service boolean derivation from low-bit immediates

**Dependency and Supply Chain:**
- Constants (STORAGE_ACCESS_*_COST, MSG_VALUE_SIMULATOR_ADDITIVE_COST, ERGS_PER_CODE_WORD_DECOMMITTMENT, stipend constants) sourced from zkevm_opcode_defs::system_params — silent change risk if pin moves
- deny.toml policy enforcement and license drift across deps
- primitive_types / enum_dispatch / arbitrary version pinning

**Input Validation Vulnerabilities:**
- SQL injection via unsanitized user input
- Command injection in system calls or subprocesses
- XXE injection in XML parsing
- Template injection in templating engines
- NoSQL injection in database queries
- Path traversal in file operations

**Authentication & Authorization Issues:**
- Authentication bypass logic
- Privilege escalation paths
- Session management flaws
- JWT token vulnerabilities
- Authorization logic bypasses

Additional notes:
- Even if something is only exploitable from the local network, it can still be a HIGH severity issue

ANALYSIS METHODOLOGY:

Phase 1 - Repository Context Research (Use file search tools):
- Identify existing security frameworks and libraries in use
- Look for established secure coding patterns in the codebase
- Examine existing sanitization and validation patterns
- Understand the project's security model and threat model

Phase 2 - Comparative Analysis:
- Do a deep review of the codebase
- Identify deviations from established secure practices
- Look for inconsistent security implementations
- Flag code that introduces new attack surfaces

Phase 3 - Vulnerability Assessment:
- Examine each modified file for security implications
- Trace data flow from user inputs to sensitive operations
- Look for privilege boundaries being crossed unsafely
- Identify injection points and unsafe deserialization

REQUIRED OUTPUT FORMAT:

You MUST output your findings in markdown. The markdown output should contain the file, line number, severity, category (e.g. `sql_injection` or `xss`), description, exploit scenario, and fix recommendation. 

For example:

# Vuln 1: XSS: `foo.py:42`

* Severity: High
* Description: User input from `username` parameter is directly interpolated into HTML without escaping, allowing reflected XSS attacks
* Exploit Scenario: Attacker crafts URL like /bar?q=<script>alert(document.cookie)</script> to execute JavaScript in victim's browser, enabling session hijacking or data theft
* Recommendation: Use Flask's escape() function or Jinja2 templates with auto-escaping enabled for all user inputs rendered in HTML

SEVERITY GUIDELINES:
- **HIGH**: Directly exploitable vulnerabilities leading to RCE, data breach, or authentication bypass
- **MEDIUM**: Vulnerabilities requiring specific conditions but with significant impact
- **LOW**: Defense-in-depth issues or lower-impact vulnerabilities

CONFIDENCE SCORING:
- 0.9-1.0: Certain exploit path identified, tested if possible
- 0.8-0.9: Clear vulnerability pattern with known exploitation methods
- 0.7-0.8: Suspicious pattern requiring specific conditions to exploit
- Below 0.7: Don't report (too speculative)

FINAL REMINDER:
Focus on HIGH and MEDIUM findings only. Better to miss some theoretical issues than flood the report with false positives. Each finding should be something a security engineer would confidently raise in a PR review.

FALSE POSITIVE FILTERING:

> You do not need to run commands to reproduce the vulnerability, just read the code to determine if it is a real vulnerability. Do not use the bash tool or write to any files.
>
> HARD EXCLUSIONS - Automatically exclude findings matching these patterns:
<!-- > 1. Denial of Service (DOS) vulnerabilities or resource exhaustion attacks. - DON'T EXCLUDE -->
> 2. Secrets or credentials stored on disk if they are otherwise secured.
<!-- > 3. Rate limiting concerns or service overload scenarios. - DON'T EXCLUDE -->
> 4. Memory consumption or CPU exhaustion issues.
> 5. Lack of input validation on non-security-critical fields without proven security impact.
> 6. Input sanitization concerns for GitHub Action workflows unless they are clearly triggerable via untrusted input.
> 7. A lack of hardening measures. Code is not expected to implement all security best practices, only flag concrete vulnerabilities.
<!-- > 8. Race conditions or timing attacks that are theoretical rather than practical issues. Only report a race condition if it is concretely problematic. - DON'T EXCLUDE -->
> 9. Vulnerabilities related to outdated third-party libraries. These are managed separately and should not be reported here.
<!-- > 10. Memory safety issues such as buffer overflows or use-after-free-vulnerabilities are impossible in rust. Do not report memory safety issues in rust or any other memory safe languages. - DON'T EXCLUDE -->
> 11. Files that are only unit tests or only used as part of running tests.
> 12. Log spoofing concerns. Outputting un-sanitized user input to logs is not a vulnerability.
> 13. SSRF vulnerabilities that only control the path. SSRF is only a concern if it can control the host or protocol.
> 14. Including user-controlled content in AI system prompts is not a vulnerability.
> 15. Regex injection. Injecting untrusted content into a regex is not a vulnerability.
> 16. Regex DOS concerns.
> 16. Insecure documentation. Do not report any findings in documentation files such as markdown files.
> 17. A lack of audit logs is not a vulnerability.
> 
> PRECEDENTS -
> 1. Logging high value secrets in plaintext is a vulnerability. Logging URLs is assumed to be safe.
> 2. UUIDs can be assumed to be unguessable and do not need to be validated.
> 3. Environment variables and CLI flags are trusted values. Attackers are generally not able to modify them in a secure environment. Any attack that relies on controlling an environment variable is invalid.
> 4. Resource management issues such as memory or file descriptor leaks are not valid.
> 5. Subtle or low impact web vulnerabilities such as tabnabbing, XS-Leaks, prototype pollution, and open redirects should not be reported unless they are extremely high confidence.
> 6. React and Angular are generally secure against XSS. These frameworks do not need to sanitize or escape user input unless it is using dangerouslySetInnerHTML, bypassSecurityTrustHtml, or similar methods. Do not report XSS vulnerabilities in React or Angular components or tsx files unless they are using unsafe methods.
> 7. Most vulnerabilities in github action workflows are not exploitable in practice. Before validating a github action workflow vulnerability ensure it is concrete and has a very specific attack path.
> 8. A lack of permission checking or authentication in client-side JS/TS code is not a vulnerability. Client-side code is not trusted and does not need to implement these checks, they are handled on the server-side. The same applies to all flows that send untrusted data to the backend, the backend is responsible for validating and sanitizing all inputs.
> 9. Only include MEDIUM findings if they are obvious and concrete issues.
> 10. Most vulnerabilities in ipython notebooks (*.ipynb files) are not exploitable in practice. Before validating a notebook vulnerability ensure it is concrete and has a very specific attack path where untrusted input can trigger the vulnerability.
> 11. Logging non-PII data is not a vulnerability even if the data may be sensitive. Only report logging vulnerabilities if they expose sensitive information such as secrets, passwords, or personally identifiable information (PII).
> 12. Command injection vulnerabilities in shell scripts are generally not exploitable in practice since shell scripts generally do not run with untrusted user input. Only report command injection vulnerabilities in shell scripts if they are concrete and have a very specific attack path for untrusted input.
> 
> SIGNAL QUALITY CRITERIA - For remaining findings, assess:
> 1. Is there a concrete, exploitable vulnerability with a clear attack path?
> 2. Does this represent a real security risk vs theoretical best practice?
> 3. Are there specific code locations and reproduction steps?
> 4. Would this finding be actionable for a security team?
> 
> For each finding, assign a confidence score from 1-10:
> - 1-3: Low confidence, likely false positive or noise
> - 4-6: Medium confidence, needs investigation
> - 7-10: High confidence, likely true vulnerability

START ANALYSIS:

Begin your analysis now. Do this in 3 steps:

1. Use a sub-task to identify vulnerabilities. Use the repository exploration tools to understand the codebase context. In the prompt for this sub-task, include all of the above.
2. Then for each vulnerability identified by the above sub-task, create a new sub-task to filter out false-positives. Launch these sub-tasks as parallel sub-tasks. In the prompt for these sub-tasks, include everything in the "FALSE POSITIVE FILTERING" instructions.
3. Filter out any vulnerabilities where the sub-task reported a confidence less than 4.

Your final reply must contain the markdown reports and nothing else.