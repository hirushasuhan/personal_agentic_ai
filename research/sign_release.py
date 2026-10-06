"""
Release signing tool - run on an OFFLINE machine that holds the private key. Never on the machine
where the engine runs, and never inside the AI's reach.

  python sign_release.py --gen-key release.key            # writes private seed (hex, mode 0600), prints PUBLIC key
  python sign_release.py --dir build/ --version 0.3.0 --constitution ../docs/CONSTITUTION.md --key release.key

Writes manifest.json + manifest.sig into --dir. Requires the `cryptography` package (constant-time
signing); the stdlib ed25519_ref.sign is for test fixtures only.
"""

import argparse
import hashlib
import os
import sys

from updater import MANIFEST, SIGNATURE, build_manifest


def _crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        return serialization, Ed25519PrivateKey
    except ImportError:
        sys.exit("signing requires the 'cryptography' package: pip install cryptography")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gen-key", metavar="FILE")
    ap.add_argument("--dir")
    ap.add_argument("--version")
    ap.add_argument("--product", default="pai-core")
    ap.add_argument("--constitution", help="path of the Constitution file whose SHA-256 is pinned in the trust root")
    ap.add_argument("--key", help="private seed file (hex)")
    a = ap.parse_args(argv)
    serialization, Ed25519PrivateKey = _crypto()

    if a.gen_key:
        if os.path.exists(a.gen_key):
            sys.exit(f"{a.gen_key} already exists; refusing to overwrite a private key")
        parent = os.path.dirname(a.gen_key)
        if parent:
            os.makedirs(parent, exist_ok=True)
        k = Ed25519PrivateKey.generate()
        seed = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        fd = os.open(a.gen_key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(seed.hex())
        pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        print("PUBLIC KEY (put in trust.json):", pub.hex())
        return 0

    if not (a.dir and a.version and a.constitution and a.key):
        ap.error("--dir, --version, --constitution and --key are required for signing")
    with open(a.constitution, "rb") as f:
        const = hashlib.sha256(f.read()).hexdigest()
    with open(a.key, encoding="ascii") as f:
        k = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(f.read().strip()))
    manifest = build_manifest(a.dir, a.product, a.version, const)
    with open(os.path.join(a.dir, MANIFEST), "wb") as f:
        f.write(manifest)
    with open(os.path.join(a.dir, SIGNATURE), "wb") as f:
        f.write(k.sign(manifest))
    print(f"signed {a.product} {a.version}; Constitution sha256 = {const}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
