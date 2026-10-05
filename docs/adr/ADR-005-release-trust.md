# ADR-005 — External trust anchor for self-updates (risk R4)

**Status:** Accepted, prototyped · **Date:** 2026-10-05

## Context
The original design embedded a hash of the Safety Constitution "in the binary's ROM". On a normal PC there is no ROM: a program able to rewrite its own binary can rewrite the embedded hash and the checker. Trust cannot originate inside the thing being trusted.

## Decision
1. **Offline signing key.** Releases are signed with Ed25519 on a machine the engine never touches (`research/sign_release.py`). The engine's machine holds only public keys.
2. **Separate updater.** `research/updater.py` is a different program with different privileges. The trust root (`trust.json`: public keys, revocations, **pinned Constitution SHA-256**) and the install directory are writable only by the updater's account. The engine calls `trust_root_is_protected()` at start-up and **refuses to run if it could write there** (fail closed).
3. **The updater owns the Constitution hash.** A release built against a different Constitution is rejected. Changing the Constitution is a human act: edit `docs/CONSTITUTION.md`, re-sign, and update the trust root.
4. **Strict release verification:** signature over the exact manifest bytes · key not revoked · product match · strictly increasing version (anti-rollback counter) · every file listed with size + SHA-256 · safe relative paths · symlinks and unlisted files rejected · staged copy re-verified (TOCTOU) · atomic install · previous release kept; rollback re-verifies and never lowers the counter.

## Tested (`tests/test_updater.py`, 23 tests)
Tampered payload/manifest, wrong/revoked key, garbage and malleated signatures, rollback/replay, Constitution drift, unlisted files, path traversal, symlinks, oversize manifest, tampered installed release, plus RFC 8032 vector 1 and a cross-check against `cryptography`.

## Limits
* Privilege separation is OS configuration (separate Windows account + ACLs) that the Phase 2/4 installer must perform; Python cannot enforce it.
* `ed25519_ref.py` is verify-grade only (not constant-time signing); Rust will use a vetted library.
* Key custody, backup and rotation procedure must be written before the first real release.
* A compromised signing machine or a compromised OS is out of scope.
