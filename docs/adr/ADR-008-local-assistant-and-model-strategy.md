# ADR-008 — Local assistant and model strategy (risks R8–R12)

**Status:** Accepted (owner direction, 2026-10-07) · **Owner decision D6** · **Date:** 2026-10-07
**Relates to:** ADR-001 (reasoner strategy), ADR-005 (signed releases), ADR-006 (capabilities and taint), ADR-007 (symbolic engine, experimental)
**Detailed specification:** [`../LOCAL_ASSISTANT_SPEC.md`](../LOCAL_ASSISTANT_SPEC.md)

## Context
The owner's practical goal is a **simple, local, stateless system** that can (a) analyze code folders, documents, web pages and business datasets (including forecasts) and (b) write and test code, communicating comfortably in Singlish. Constraints: no budget for cloud GPUs, a single developer, one laptop (AMD Ryzen 5 8645HS, 16 GB RAM, Radeon 760M iGPU).

Facts established so far:
* Measured by the owner on that laptop (5 cold runs each, recorded in `research/model_profiles.json`): `llama3.2:1b` and `llama3.2:3b` run fully offloaded to the iGPU; the host available-RAM drop was about 705 MB (max 733 MB) and 761 MB (max 816 MB).
* Review of real answers from both models showed factual and technical errors (for example in explanations of Rust ownership). Small local models cannot be trusted without verification.
* ADR-007's symbolic engine is a deterministic, rule-based prototype. It is not a general question-answering or coding engine and stays experimental.
* Training a model that is competent at coding from scratch needs far more compute and data than a laptop or free-tier GPUs provide. That is an expectation based on published scaling practice, not something this project has measured.

## Decision
1. **Three layers.**
   * **L1 — own system (built now):** planner, tool broker, verify loop (generate → static guard → run tests in a restricted process → repair), file/document/web/data ingestion, stateless purge, outbound and capability policies, hardware-aware scheduling, and a Singlish front-end.
   * **L2 — pluggable "code brain":** one or more **open-weights** models served locally behind the existing `Reasoner` interface and chosen by task and hardware tier. Each model gets a *model card* (source, licence, SHA-256 of the weights, measured `host_delta_mb`).
   * **L3 — own-model research track (gated):** fine-tuning, not pre-training. See decisions 3–5.
2. **Owner decision D6:** the earlier "no third-party models" preference is relaxed for **L2 only**, as a replaceable component, until an own model passes the promotion gate below. ADR-010 (proposed, D7) additionally allows opt-in cloud providers as a separate backend kind; they are not part of the own-model claim. Licences must be checked before a model is added; use of a model's outputs to train another model must be allowed by that model's licence.
3. **"Own model" definition:** the owner's own weights delta (LoRA adapter or fine-tune) on a pretrained small open base. The base remains third-party. From-scratch pre-training is deferred until compute and data exist; the project does not claim otherwise.
4. **Data engine (self-play, local):** overnight, L1 generates small coding problems with unit tests; L2 models attempt them; only trajectories whose tests **pass in the restricted runner** are kept. Trajectories whose context was tainted (`context_tainted`) are excluded. Private user data is **not** used for training unless the owner opts in explicitly (this is the same explicit exception to statelessness as the Phase 5 personal knowledge store: encrypted, local, off by default).
5. **Hardware-aware training:** training or fine-tuning runs only when the telemetry tier is HIGH, the machine is on AC power and the CPU is idle, and stops on pressure.
6. **Adaptive model router (amendment 2026-10-07):** L2 is a *set* of models, chosen per task and per current machine condition by a deterministic, explainable router (design in `LOCAL_ASSISTANT_SPEC.md` §3.3). It is adopted only if it beats the best single model under the same RAM budgets on the frozen evaluations. Model names come from the owner's allow-list only; content can never select a model.
7. **Candidate models for the first bake-off** (none adopted): `qwen2.5-coder:7b` and `1.5b`, `qwen3.5:4b`, `gemma4:e2b`, reference `llama3.2:3b`. Licences reported by secondary sources are re-read on official model cards before use. Excluded: models too large for the hardware (≈ 14 GB and up) and models with custom or restrictive licences.
8. **Numbers come from code:** forecasts and other quantitative results are computed by deterministic, tested code with backtests and uncertainty ranges. A language model may only narrate values the code produced.

## Promotion gate for any new model or adapter (extends RSI Tier 3/4)
A candidate may enter the router only if **all** hold on frozen, versioned evaluation sets that the candidate has never trained on:
* It beats the current router baseline on the coding evaluation (pass@1 by unit tests) by a pre-registered margin.
* It is not worse on the prompt-injection and file-analysis safety suites.
* It does not regress the Singlish intent evaluation.
* It is delivered as a signed release through the updater (ADR-005) and the previous version stays available for rollback.
If any condition fails, the previous configuration stays in place.

## Consequences
* A useful, honest assistant exists after milestones M1–M3 without any new model training.
* Expectations: small open models are far weaker than frontier coding agents. The verify loop narrows the gap on small, testable tasks; it does not remove it.
* Three new risk classes are tracked (THREAT_MODEL T15–T20): untrusted local files, model-generated code execution, local web UI, self-training poisoning/memorization, misleading numeric output, model supply chain.
* The symbolic engine (ADR-007) is repurposed as a *checker* (evidence and grounding validation) rather than a generator.

## Alternatives considered
* **From-scratch pre-training on the laptop or free GPU tiers:** rejected; capability would be well below the open models (expectation, see Context).
* **Distillation from closed models:** rejected; licence and terms-of-service risk.
* **Continual training on all user activity:** rejected as default; conflicts with statelessness and privacy (T18).

## If reversed
Keep L1 and the `Reasoner` interface; restrict L2 to the symbolic engine only (very limited coding ability) or to a single owner-approved model.
