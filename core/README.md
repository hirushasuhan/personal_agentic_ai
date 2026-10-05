# core/ — Rust engine (Phase 3)

Charter (ADR-004): engine, planner, stateless purge (`zeroize`), network client, URL policy, capability broker, updater.

First deliverable = **vertical slice VS2**: a Rust CLI that reproduces `python main.py --telemetry --json` and passes
`research/conformance/tier_policy_vectors.json` and `url_policy_vectors.json` in CI. Do not start further slices before VS2 is green.

Reference behaviour lives in `research/` (see `docs/PROTOTYPE_SPEC.md`); the Python tests are the specification.
