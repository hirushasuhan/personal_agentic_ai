"""
Signed-release updater (review risk R4).

WHY: a self-modifying engine cannot protect itself - if it can rewrite its binary it can rewrite any
hash embedded in it. Trust must therefore come from OUTSIDE the engine:

  * releases are signed with an Ed25519 key that never exists on this machine (offline signing,
    see sign_release.py); this machine only holds PUBLIC keys
  * this updater is a SEPARATE program run with its own privileges. The trust root (public keys, the
    pinned Constitution hash) and the install directory are writable only by the updater's account,
    not by the engine's. `trust_root_is_protected()` lets the engine fail closed at start-up if not.
  * the updater - not the engine - owns the Constitution hash: a release whose Constitution differs
    from the pinned one is refused, so intent drift needs a human-signed trust-root change.

Checks on every release: signature over the EXACT manifest bytes (no re-serialisation), key not
revoked, product match, strictly increasing version (anti-rollback counter), pinned Constitution hash,
every file listed with size + SHA-256, safe relative paths, no unlisted files, and a second full
verification of the staged copy (TOCTOU). Install is atomic; the previous release is kept for rollback.

Prototype scope: file-level logic is real and tested; OS-level privilege separation (separate Windows
account / ACLs) is configuration the Phase 2/4 installer must perform.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import ed25519_ref

MANIFEST = "manifest.json"
SIGNATURE = "manifest.sig"
MAX_MANIFEST_BYTES = 1024 * 1024
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class UpdateRejected(Exception):
    """A release failed verification; nothing was installed."""


@dataclass
class VerifiedRelease:
    version: str
    key_id: str
    files: List[str]
    manifest: Dict


def parse_version(v: str) -> Tuple[int, int, int]:
    if not isinstance(v, str) or not _VERSION_RE.match(v):
        raise UpdateRejected(f"bad version '{v}'")
    a, b, c = (int(x) for x in v.split("."))
    return a, b, c


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_manifest(release_dir: str, product: str, version: str, constitution_sha256: str) -> bytes:
    """Used by the signing tool: lists every payload file with size + SHA-256."""
    parse_version(version)
    files = {}
    for dirpath, _, names in os.walk(release_dir):
        for n in sorted(names):
            full = os.path.join(dirpath, n)
            rel = os.path.relpath(full, release_dir).replace(os.sep, "/")
            if rel in (MANIFEST, SIGNATURE):
                continue
            files[rel] = {"sha256": sha256_file(full), "size": os.path.getsize(full)}
    doc = {"format": 1, "product": product, "version": version, "constitution_sha256": constitution_sha256, "files": files}
    return json.dumps(doc, indent=2, sort_keys=True).encode("utf-8")


def _atomic_write_json(path: str, obj) -> None:
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def trust_root_is_protected(path: str) -> bool:
    """Engine-side start-up check: returns True only if THIS process cannot write into `path`.
    The engine must refuse to run (fail closed) if the trust root or install dir is writable by it."""
    probe = os.path.join(path, f".probe-{os.getpid()}")
    try:
        with open(probe, "x"):
            pass
    except OSError:
        return True
    try:
        os.unlink(probe)
    except OSError:
        pass
    return False


class Updater:
    def __init__(self, trust_root: str, install_root: str, product: str = "pai-core"):
        self.trust_root, self.install_root, self.product = trust_root, install_root, product
        with open(os.path.join(trust_root, "trust.json"), encoding="utf-8") as f:
            trust = json.load(f)
        self.keys: Dict[str, bytes] = {}
        for k in trust["keys"]:
            if not k.get("revoked", False):
                pub = bytes.fromhex(k["public_hex"])
                if len(pub) != 32:
                    raise ValueError(f"bad public key {k['id']}")
                self.keys[k["id"]] = pub
        self.constitution_sha256: str = trust["constitution_sha256"]
        os.makedirs(os.path.join(install_root, "releases"), exist_ok=True)
        self._state_path = os.path.join(install_root, "state.json")
        self._current_path = os.path.join(install_root, "current.json")

    # ------------------------------------------------------------------ state
    def _state(self) -> Dict:
        if os.path.exists(self._state_path):
            with open(self._state_path, encoding="utf-8") as f:
                return json.load(f)
        return {"highest_seen": "0.0.0"}

    def current_version(self) -> Optional[str]:
        if not os.path.exists(self._current_path):
            return None
        with open(self._current_path, encoding="utf-8") as f:
            return json.load(f)["version"]

    # ----------------------------------------------------------- verification
    def verify_release(self, release_dir: str, check_rollback: bool = True) -> VerifiedRelease:
        mpath, spath = os.path.join(release_dir, MANIFEST), os.path.join(release_dir, SIGNATURE)
        if not (os.path.isfile(mpath) and os.path.isfile(spath)):
            raise UpdateRejected("manifest or signature missing")
        if os.path.getsize(mpath) > MAX_MANIFEST_BYTES:
            raise UpdateRejected("manifest too large")
        with open(mpath, "rb") as f:
            manifest_bytes = f.read()
        with open(spath, "rb") as f:
            raw_sig = f.read(512)
        sig = raw_sig  # 64 raw bytes (do NOT strip: a binary signature may end in whitespace-valued bytes)
        if len(raw_sig) != 64:
            try:
                sig = bytes.fromhex(raw_sig.decode("ascii").strip())  # also accept hex text
            except (ValueError, UnicodeDecodeError):
                sig = b""

        key_id = next((kid for kid, pub in self.keys.items() if ed25519_ref.verify(pub, manifest_bytes, sig)), None)
        if key_id is None:
            raise UpdateRejected("signature invalid or signed by an unknown/revoked key")

        try:
            m = json.loads(manifest_bytes.decode("utf-8"))
            files = m["files"]
            version, product, const = m["version"], m["product"], m["constitution_sha256"]
        except (ValueError, KeyError, TypeError):
            raise UpdateRejected("malformed manifest")
        if m.get("format") != 1 or product != self.product:
            raise UpdateRejected("wrong manifest format or product")
        if const != self.constitution_sha256:
            raise UpdateRejected("Constitution hash differs from the pinned trust-root value")
        v = parse_version(version)
        if check_rollback and v <= parse_version(self._state()["highest_seen"]):
            raise UpdateRejected(f"version {version} is not newer than highest seen {self._state()['highest_seen']} (anti-rollback)")
        if not isinstance(files, dict) or not files:
            raise UpdateRejected("manifest lists no files")

        root = os.path.realpath(release_dir)
        for rel, meta in files.items():
            if (not isinstance(rel, str) or rel.startswith(("/", "\\")) or "\\" in rel or ":" in rel
                    or any(part in ("..", "", ".") for part in rel.split("/"))):
                raise UpdateRejected(f"unsafe path in manifest: {rel!r}")
            full = os.path.realpath(os.path.join(root, *rel.split("/")))
            if os.path.commonpath([full, root]) != root or os.path.islink(os.path.join(root, *rel.split("/"))):
                raise UpdateRejected(f"path escapes release directory: {rel!r}")
            if not os.path.isfile(full):
                raise UpdateRejected(f"listed file missing: {rel}")
            if not isinstance(meta, dict) or not _SHA_RE.match(str(meta.get("sha256", ""))):
                raise UpdateRejected(f"bad digest entry for {rel}")
            if os.path.getsize(full) != meta.get("size"):
                raise UpdateRejected(f"size mismatch: {rel}")
            if sha256_file(full) != meta["sha256"]:
                raise UpdateRejected(f"SHA-256 mismatch (tampered?): {rel}")

        listed = set(files) | {MANIFEST, SIGNATURE}
        for dirpath, _, names in os.walk(root):
            for n in names:
                rel = os.path.relpath(os.path.join(dirpath, n), root).replace(os.sep, "/")
                if rel not in listed:
                    raise UpdateRejected(f"unlisted file in release: {rel}")
        return VerifiedRelease(version, key_id, sorted(files), m)

    # ---------------------------------------------------------------- install
    def install(self, release_dir: str) -> VerifiedRelease:
        rel = self.verify_release(release_dir)
        releases = os.path.join(self.install_root, "releases")
        dest = os.path.join(releases, rel.version)
        if os.path.exists(dest):
            raise UpdateRejected(f"version {rel.version} already installed")
        tmp = tempfile.mkdtemp(prefix=".staging-", dir=releases)
        try:
            for name in rel.files + [MANIFEST, SIGNATURE]:
                target = os.path.join(tmp, *name.split("/"))
                os.makedirs(os.path.dirname(target), exist_ok=True)
                shutil.copyfile(os.path.join(release_dir, *name.split("/")), target)
            self.verify_release(tmp, check_rollback=True)  # TOCTOU: verify what we actually staged
            os.replace(tmp, dest)
        except BaseException:
            shutil.rmtree(tmp, ignore_errors=True)
            raise
        previous = self.current_version()
        _atomic_write_json(self._current_path, {"version": rel.version, "previous": previous})
        _atomic_write_json(self._state_path, {"highest_seen": rel.version})
        return rel

    def rollback(self) -> str:
        """Emergency reversion to the previously installed release (re-verified first).
        Deliberately does NOT lower the anti-rollback counter: nothing newer-than-current can be replayed."""
        if not os.path.exists(self._current_path):
            raise UpdateRejected("nothing installed")
        with open(self._current_path, encoding="utf-8") as f:
            cur = json.load(f)
        prev = cur.get("previous")
        if not prev:
            raise UpdateRejected("no previous release to roll back to")
        self.verify_release(os.path.join(self.install_root, "releases", prev), check_rollback=False)
        _atomic_write_json(self._current_path, {"version": prev, "previous": None})
        return prev
