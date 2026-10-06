# core/ — Rust Engine (Phase 2 VS2)

Charter (ADR-004): engine, planner, stateless purge (`zeroize`), network client, URL policy, capability broker, updater.

## Vertical Slice 2 (VS2) Status: COMPLETE
`pai-core` is a stateless, pure Rust implementation of the PAI resource allocation and outbound security policies:
1. `src/tier.rs`: Pure hardware budgeting policy mirroring Python `_calculate_budget`.
2. `src/url_policy.rs`: Pure URL validation and Canonical Blocked CIDR table (RFC 1918, RFC 3927, loopback, multicast, etc.).
3. `src/conformance.rs`: Golden vector runner and differential fuzz validator.
4. `src/main.rs`: CLI runner for `--conformance <DIR>` and `--differential <FILE>`.

### Design & Safety Guarantees
- **No Unsafe Code**: Contains zero unsafe blocks.
- **No Fake Telemetry**: Hardcoded dummy telemetry was completely removed per ADR-004 and the claims policy. Native OS telemetry will land in VS3.
- **Zero Network Crate Dependencies**: Strictly uses `serde` + `serde_json` and standard library networking types (`std::net`).
- **Differential Verification**: 10,000 differential fuzz inputs verified against Python specification with 0 mismatches.
