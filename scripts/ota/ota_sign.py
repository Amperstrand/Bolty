#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def parse_args() -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Sign Bolty OTA manifests")
    parser.add_argument("manifest", type=Path, help="Path to manifest.json")
    parser.add_argument("firmware", type=Path, help="Path to firmware binary")
    parser.add_argument(
        "--private-key",
        type=Path,
        default=script_dir / "keys" / "ota_signing_key.pem",
        help="Path to OTA signing private key",
    )
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    args = parse_args()

    manifest = json.loads(args.manifest.read_text())
    version_code = manifest.get("version_code")
    if not isinstance(version_code, int) or version_code <= 0:
        raise ValueError("manifest.json must contain a positive integer version_code")

    sha256_hex = sha256_file(args.firmware)
    payload = f"{version_code}{sha256_hex}".encode("utf-8")

    private_key = serialization.load_pem_private_key(
        args.private_key.read_bytes(),
        password=None,
    )
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise TypeError("private key must be an EC private key")

    signature = private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    manifest["sha256"] = sha256_hex
    manifest["signature"] = base64.b64encode(signature).decode("ascii")
    args.manifest.write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
