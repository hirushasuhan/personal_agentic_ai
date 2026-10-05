import hashlib
import json
import os
import shutil
import tempfile
import unittest

import _bootstrap  # noqa: F401
import ed25519_ref
from updater import (MANIFEST, SIGNATURE, UpdateRejected, Updater, build_manifest, trust_root_is_protected)

SEED = bytes(range(32))                  # TEST-ONLY key
OTHER_SEED = bytes(range(1, 33))
PUB = ed25519_ref.secret_to_public(SEED)
CONSTITUTION = b"1. Privacy first.\n"
CONST_SHA = hashlib.sha256(CONSTITUTION).hexdigest()


def make_release(base, version="0.3.0", files=None, seed=SEED, const=CONST_SHA, mutate=None):
    d = tempfile.mkdtemp(dir=base)
    for name, data in (files or {"pai_core.bin": b"engine v" + version.encode(), "cfg/default.json": b"{}"}).items():
        os.makedirs(os.path.dirname(os.path.join(d, name)), exist_ok=True)
        with open(os.path.join(d, name), "wb") as f:
            f.write(data)
    manifest = build_manifest(d, "pai-core", version, const)
    if mutate:
        manifest = mutate(manifest)
    with open(os.path.join(d, MANIFEST), "wb") as f:
        f.write(manifest)
    with open(os.path.join(d, SIGNATURE), "wb") as f:
        f.write(ed25519_ref.sign(seed, manifest))
    return d


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.trust = os.path.join(self.tmp, "trust"); os.makedirs(self.trust)
        self.install = os.path.join(self.tmp, "install"); os.makedirs(self.install)
        self.src = os.path.join(self.tmp, "src"); os.makedirs(self.src)
        self.write_trust()

    def write_trust(self, revoked=False, const=CONST_SHA):
        with open(os.path.join(self.trust, "trust.json"), "w") as f:
            json.dump({"keys": [{"id": "rel-1", "public_hex": PUB.hex(), "revoked": revoked}], "constitution_sha256": const}, f)

    def updater(self):
        return Updater(self.trust, self.install)

    def assertRejected(self, release, text=""):
        u = self.updater()
        before = u.current_version()
        with self.assertRaises(UpdateRejected) as cm:
            u.install(release)
        self.assertIn(text, str(cm.exception))
        self.assertEqual(u.current_version(), before)            # nothing changed
        self.assertEqual([n for n in os.listdir(os.path.join(self.install, "releases")) if n.startswith(".staging")], [])


class Happy(Base):
    def test_valid_release_installs(self):
        rel = self.updater().install(make_release(self.src))
        u = self.updater()
        self.assertEqual(rel.version, "0.3.0")
        self.assertEqual(rel.key_id, "rel-1")
        self.assertEqual(u.current_version(), "0.3.0")
        self.assertTrue(os.path.isfile(os.path.join(self.install, "releases", "0.3.0", "cfg", "default.json")))

    def test_hex_text_signature_accepted(self):
        d = make_release(self.src)
        with open(os.path.join(d, SIGNATURE), "rb") as f:
            raw = f.read()
        with open(os.path.join(d, SIGNATURE), "w") as f:
            f.write(raw.hex() + "\n")
        self.assertEqual(self.updater().install(d).version, "0.3.0")

    def test_upgrade_then_rollback(self):
        u = self.updater()
        u.install(make_release(self.src, "0.3.0"))
        u.install(make_release(self.src, "0.4.0"))
        self.assertEqual(u.current_version(), "0.4.0")
        self.assertEqual(u.rollback(), "0.3.0")
        self.assertEqual(u.current_version(), "0.3.0")
        # the anti-rollback counter was NOT lowered: an old signed release still can't be replayed
        with self.assertRaises(UpdateRejected):
            u.install(make_release(self.src, "0.3.5"))


class Attacks(Base):
    def test_tampered_payload(self):
        d = make_release(self.src)
        with open(os.path.join(d, "pai_core.bin"), "ab") as f:
            f.write(b"backdoor")
        self.assertRejected(d, "mismatch")

    def test_same_size_tamper_detected_by_hash(self):
        d = make_release(self.src)
        p = os.path.join(d, "cfg", "default.json")
        with open(p, "wb") as f:
            f.write(b"[]")  # same size as "{}" - only the hash can catch this
        self.assertRejected(d, "SHA-256 mismatch")

    def test_tampered_manifest_breaks_signature(self):
        d = make_release(self.src)
        with open(os.path.join(d, MANIFEST), "ab") as f:
            f.write(b" ")
        self.assertRejected(d, "signature invalid")

    def test_signed_by_unknown_key(self):
        self.assertRejected(make_release(self.src, seed=OTHER_SEED), "unknown/revoked key")

    def test_revoked_key(self):
        self.write_trust(revoked=True)
        self.assertRejected(make_release(self.src), "unknown/revoked key")

    def test_missing_signature(self):
        d = make_release(self.src)
        os.unlink(os.path.join(d, SIGNATURE))
        self.assertRejected(d, "missing")

    def test_garbage_signature(self):
        d = make_release(self.src)
        with open(os.path.join(d, SIGNATURE), "wb") as f:
            f.write(b"\x00" * 64)
        self.assertRejected(d, "signature invalid")

    def test_malleated_signature_rejected(self):
        d = make_release(self.src)
        with open(os.path.join(d, SIGNATURE), "rb") as f:
            sig = f.read()
        s = int.from_bytes(sig[32:], "little") + ed25519_ref.q
        with open(os.path.join(d, SIGNATURE), "wb") as f:
            f.write(sig[:32] + (s % 2 ** 256).to_bytes(32, "little"))
        self.assertRejected(d, "signature invalid")

    def test_rollback_and_replay_blocked(self):
        u = self.updater()
        u.install(make_release(self.src, "0.4.0"))
        self.assertRejected(make_release(self.src, "0.3.0"), "anti-rollback")
        self.assertRejected(make_release(self.src, "0.4.0"), "anti-rollback")

    def test_constitution_drift_rejected(self):
        self.assertRejected(make_release(self.src, const=hashlib.sha256(b"weakened").hexdigest()), "Constitution")

    def test_unlisted_file_rejected(self):
        d = make_release(self.src)
        with open(os.path.join(d, "extra.dll"), "wb") as f:
            f.write(b"x")
        self.assertRejected(d, "unlisted")

    def test_path_traversal_in_signed_manifest(self):
        for evil in ("../evil.bin", "/abs/evil.bin", "a\\..\\b", "a/../../b", "C:evil"):
            def mutate(m, evil=evil):
                doc = json.loads(m)
                doc["files"][evil] = {"sha256": "0" * 64, "size": 1}
                return json.dumps(doc).encode()
            self.assertRejected(make_release(self.src, mutate=mutate), "unsafe path")

    @unittest.skipIf(os.name == "nt", "symlinks need privileges on Windows")
    def test_symlinked_payload_rejected(self):
        d = make_release(self.src)
        outside = os.path.join(self.tmp, "outside.bin")
        with open(outside, "wb") as f:
            f.write(b"engine v0.3.0")
        os.unlink(os.path.join(d, "pai_core.bin"))
        os.symlink(outside, os.path.join(d, "pai_core.bin"))
        self.assertRejected(d, "escapes")

    def test_oversize_manifest(self):
        d = make_release(self.src)
        with open(os.path.join(d, MANIFEST), "wb") as f:
            f.write(b" " * (1024 * 1024 + 1))
        self.assertRejected(d, "too large")

    def test_installed_release_tampering_blocks_rollback(self):
        u = self.updater()
        u.install(make_release(self.src, "0.3.0"))
        u.install(make_release(self.src, "0.4.0"))
        with open(os.path.join(self.install, "releases", "0.3.0", "pai_core.bin"), "ab") as f:
            f.write(b"x")
        with self.assertRaises(UpdateRejected):
            u.rollback()
        self.assertEqual(u.current_version(), "0.4.0")


class TrustRoot(unittest.TestCase):
    def test_writable_directory_is_reported_unprotected(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(trust_root_is_protected(d))
            self.assertEqual(os.listdir(d), [])  # probe file cleaned up

    @unittest.skipIf(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0), "needs a non-root POSIX user")
    def test_read_only_directory_is_protected(self):
        d = tempfile.mkdtemp()
        os.chmod(d, 0o555)
        try:
            self.assertTrue(trust_root_is_protected(d))
        finally:
            os.chmod(d, 0o755); os.rmdir(d)


class Crypto(unittest.TestCase):
    def test_rfc8032_vector_1(self):
        sk = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        pk = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        sig = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        self.assertEqual(ed25519_ref.secret_to_public(sk), pk)
        self.assertEqual(ed25519_ref.sign(sk, b""), sig)
        self.assertTrue(ed25519_ref.verify(pk, b"", sig))
        self.assertFalse(ed25519_ref.verify(pk, b"x", sig))

    def test_bad_lengths_return_false(self):
        self.assertFalse(ed25519_ref.verify(b"short", b"m", b"\x00" * 64))
        self.assertFalse(ed25519_ref.verify(PUB, b"m", b"\x00" * 10))

    def test_cross_check_with_cryptography_package(self):
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        except ImportError:
            self.skipTest("cryptography not installed")
        for msg in (b"", b"hello", os.urandom(1000)):
            k = Ed25519PrivateKey.from_private_bytes(SEED)
            self.assertEqual(k.sign(msg), ed25519_ref.sign(SEED, msg))
            self.assertTrue(ed25519_ref.verify(PUB, msg, k.sign(msg)))


if __name__ == "__main__":
    unittest.main()
