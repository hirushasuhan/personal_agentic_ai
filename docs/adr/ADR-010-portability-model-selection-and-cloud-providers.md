# ADR-010 — Portable hardware profiles, user-selectable models and optional cloud providers

**Status:** Proposed (owner request, 2026-10-07) · **Owner decision D7 (pending confirmation)** · **Date:** 2026-10-07

## Context
The owner wants `pai` to work on other PCs, not only on the development laptop; to let the user choose which models are used; and to allow, besides local models, the paid APIs of the main AI providers when the user supplies a key. All measurements so far (model cards, `host_delta_mb`) come from one machine (Ryzen 5 8645HS, 16 GB, Radeon 760M iGPU). Cloud providers change two assumptions of the design: data leaves the machine, and there is a secret (the API key) to protect.

## Decisions
1. **Per-machine calibration.** Model-card numbers from the owner's laptop are *priors*, not facts about another PC. `pai calibrate` runs the cold-start procedure of `docs/MEASUREMENT_PROCEDURE.md` (5 runs, median) on the current machine and writes a local **machine profile** (numbers only: RAM, CPU, GPU/iGPU, OS, per-model cold delta, latency). The router prefers the machine profile. For a model without a calibrated delta the router uses the card value multiplied by 1.5 plus the 512 MB headroom and labels the decision `uncalibrated`. The machine profile is never committed and never contains prompts or file contents.
2. **User-selectable models.** A non-secret user configuration file holds the allow-list of local models and enabled providers, preferred model per task class, and limits. `pai setup` detects the hardware, recommends models that fit, and downloads only after explicit consent, checking the SHA-256 from the model card. A model added by the user without a card is "unmeasured" (last resort, labelled) until `pai bench` produces one. Models and providers outside the allow-list are never used (T21).
3. **Provider abstraction.** The `Reasoner` interface gets two backend kinds: `local` (loopback model server, as today) and `cloud:<provider>` (official HTTPS APIs of the providers the owner enables). Each provider has a **provider card**: allowed hosts, API style, model names, context limit, price per token, data-handling statement with the URL and the date it was read, and `privacy_class = leaves_machine`. No provider is built in as "default".
4. **Privacy default is local-only.** Cloud use needs both a provider enabled in the configuration and consent for the run (`--allow-cloud`, or an interactive confirmation that lists what will be sent: file names, byte counts, provider). Files skipped as secrets are never sent. Every cloud call is written to the visible outbound log with byte counts (ADR-002) and the answer header states the provider and model used. `--offline` removes every cloud candidate.
5. **Statelessness caveat, stated plainly.** The purge zeroes local memory. It cannot erase what a provider receives or retains. Output produced with a cloud model carries a "sent to provider" notice, and the documentation must not describe cloud runs as stateless.
6. **API keys.** Keys are stored in the operating system credential store (Windows Credential Manager, macOS Keychain, Secret Service on Linux) and entered through a hidden prompt (`pai keys set`). An environment variable is a fallback, read once into a `SecureBuffer`. Keys never appear in the repository, configuration file, command-line arguments, logs, crash output, model prompts or evidence files, and must not be pasted into any assistant chat (including with the reviewer). Recommended practice: a key restricted to one project with a spend limit set at the provider.
7. **Router extension.** Cloud candidates enter the candidate set only when enabled and consented. The RAM fit rule does not apply to them; instead: network available, provider reachable, per-run and per-day spend cap (tokens × price from the provider card, counted locally), rate-limit backoff, no automatic retry loops. Order: a local model that fits and meets the task-class preference first; cloud as an explicit fallback or with `--prefer cloud`. Every decision reports reason codes and "data leaves machine: yes/no".
8. **Endpoint policy.** Provider hosts come from the provider card, not from configuration text or model output: HTTPS only, certificate verification on, no redirects to other hosts, no custom base URL unless the owner adds a host to the allow-list deliberately (T25). Cloud responses are untrusted data, fenced like any other context; tools stay disabled.
9. **Evaluation.** Cloud models are measured on the same frozen sets, with cost recorded, but are reported separately from local models and never used to claim that the local system "can do" something.
10. **Operating systems.** Windows is the reference platform. Linux and macOS use the existing Python telemetry fallback (`/proc`, psutil); the Rust `win32.rs` module stays Windows-only. A Linux CI job is added; macOS is best-effort until tested on a real machine.

## Consequences
* New threats T22–T26 (see `docs/THREAT_MODEL.md`) and two milestones, M1c (portability, calibration, model selection) and M1d (cloud providers), before M2. M2 onward is shifted by four weeks.
* The Constitution and outbound policy need an explicit "cloud provider" category; the loopback-only rule applies to local model endpoints.
* CI must not hold real keys; cloud code is tested against a local mock provider server.

## Alternatives considered
* *Local only* — simplest and strongest on privacy, but gives up quality on weak machines and the owner's request.
* *Cloud keys in a plain configuration file* — rejected (T22).
* *One universal calibration shipped with the repository* — rejected: another PC's RAM, iGPU sharing and background load differ.

## If reversed
Remove the cloud backend kind and the provider cards; keep M1c (it is useful for local models alone).
