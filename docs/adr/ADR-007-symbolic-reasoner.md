# ADR-007 — Stateless Deductive Reasoning Engine (Option B Implementation)

**Status:** Accepted (Experimental track) · **Owner decision D1** · **Date:** 2026-10-06

## Context
ADR-001 established two parallel tracks for the reasoning component:
1. **Product path (Option A):** Use an existing open-weights small model served locally (`LocalLLMReasoner`) to satisfy real user queries immediately.
2. **Research path (Option B):** A custom, knowledge-free architecture operating statelessly in ephemeral memory without massive pre-trained weights.

To prevent premature claims or deceptive stubs from masquerading as a completed engine, the research path required a rigorous, mathematically sound specification. Rather than relying on simple pattern-matching or unconditional guarantees, the custom engine must execute deterministic deductive reasoning over explicit evidence atoms, detect dialectic contradictions, and strictly enforce verifiable grounding.

## Decision
1. **Formal Evidence Atom Model:** Grounding operates over atomic propositions represented as $\langle \text{id}, \text{subject}, \text{predicate}, \text{object}, \text{polarity}, \text{source\_trust}, \text{timestamp} \rangle$.
2. **Dialectic Conflict Resolution:** Contradictory premises are detected via direct negation or functional predicate conflicts. Conflicting statements are resolved via source trust weighting or flagged as unresolvable contradictions.
3. **Budget-Bounded Execution Graph (DAG):** Reasoning steps are organized as an acyclic graph executed deterministically. Concurrency and graph depth are dynamically bounded by the active `HardwareBudget` compute tier (`COMPRESSED`, `BALANCED`, `HIGH`).
4. **Strict Grounding Validator:** Output claims must explicitly cite valid evidence atom IDs (`[ATOM-xxx]`). Uncited assertions are marked as `UNGROUNDED`.
5. **Experimental Status:** The engine is exposed via `--reasoner symbolic` (experimental prototype). The default CLI reasoner remains `TemplateReasoner` (stub) or `LocalLLMReasoner` per ADR-001 until the symbolic engine meets the formal promotion gate.

## Operational Invariants (I1 – I6)
* **I1 (Grounding):** No ungrounded claim is presented as a verified fact without an explicit UNGROUNDED marker.
* **I2 (Termination):** The execution graph is provably acyclic and bounded by budget depth ceilings.
* **I3 (Budget Containment):** Execution concurrency and memory allocations strictly adhere to `HardwareBudget`.
* **I4 (Ephemeral Purge):** All intermediate graph structures, atoms, and buffers are cleared and zeroized post-task.
* **I5 (Auditability):** Every reasoning pass generates a structured execution trace including timings and conflict resolutions.
* **I6 (AST Isolation):** All synthesized code undergoes Tier-1 AST Guard inspection before exposure.

## Safety Constraints
* AST guard allow-list enforcement (`ast_guard.py`) for all code generation.
* Ephemeral memory allocation with post-execution zeroization (`SecureBuffer`).
* Compliance with claims lint policy (zero unbacked security guarantees).

## Consequences
* The project has a mathematically sound, reproducible foundation for its custom reasoning algorithm.
* Clear separation between production model serving (ADR-001) and research prototyping.
* Property-based tests ensure invariants I1–I6 cannot silently regress.
