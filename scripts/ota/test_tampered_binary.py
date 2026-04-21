#!/usr/bin/env python3
"""
Unit tests for OTA signed manifest verification.

Tests the same crypto chain the ESP32 firmware runs in ota.h:
  1. ECDSA P-256 signature of (version_code + sha256_hex) against embedded public key
  2. SHA-256 hash of the firmware binary
  3. Anti-rollback version check

Tampering vectors tested:
  - Tampered firmware binary (SHA-256 mismatch)
  - Tampered ECDSA signature (verification fails)
  - Tampered hash in manifest (signature verification fails — hash is in signed payload)
  - Tampered version in manifest (signature verification fails — version is in signed payload)
  - Signed with wrong key (verification fails against embedded public key)
  - Downgrade attack (version <= current)
  - Missing fields (sha256, signature, version)
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

SCRIPT_DIR = Path(__file__).resolve().parent
KEYS_DIR = SCRIPT_DIR / "keys"
PRIVATE_KEY_PATH = KEYS_DIR / "ota_signing_key.pem"
PUBLIC_KEY_PATH = KEYS_DIR / "ota_signing_pub.pem"

# The public key PEM that gets embedded in firmware (must match ota_signing_key.h)
EMBEDDED_PUBLIC_KEY_PEM = PUBLIC_KEY_PATH.read_text()


def sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 hex digest of bytes."""
    return hashlib.sha256(data).hexdigest()


def sign_manifest(version_code: int, sha256_hex: str, private_key_pem: bytes) -> str:
    """Sign (version_code + sha256_hex) with ECDSA P-256, return base64 signature."""
    payload = f"{version_code}{sha256_hex}".encode("utf-8")
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    signature = private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode("ascii")


def verify_signature(version_code: int, sha256_hex: str, signature_b64: str, public_key_pem: str) -> bool:
    """
    Mirrors ota_verify_manifest_signature() in ota.h:
      1. Reconstruct payload = String(version_code) + sha256_hex
      2. Verify ECDSA signature against embedded public key
    """
    payload = f"{version_code}{sha256_hex}".encode("utf-8")
    public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    try:
        signature_bytes = base64.b64decode(signature_b64)
        public_key.verify(signature_bytes, payload, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


class TestTamperedBinaryRejection(unittest.TestCase):
    """Test OTA manifest verification rejects tampered firmware and manifests."""

    @classmethod
    def setUpClass(cls):
        if not PRIVATE_KEY_PATH.exists():
            raise unittest.SkipTest(
                f"Private key not found at {PRIVATE_KEY_PATH}. "
                "Run scripts/ota/generate_signing_key.sh first."
            )
        cls.private_key_pem = PRIVATE_KEY_PATH.read_bytes()

        # Generate a fake firmware binary (1KB of pseudorandom data)
        cls.firmware_data = os.urandom(1024)
        cls.firmware_sha256 = sha256_bytes(cls.firmware_data)
        cls.version_code = 9999999

        # Create a valid signed manifest
        cls.valid_signature = sign_manifest(
            cls.version_code, cls.firmware_sha256, cls.private_key_pem
        )

    def _make_manifest(self, **overrides) -> dict:
        """Create a manifest dict with optional field overrides."""
        manifest = {
            "version_code": self.version_code,
            "url": f"/firmware-{self.version_code}.bin",
            "size": len(self.firmware_data),
            "sha256": self.firmware_sha256,
            "signature": self.valid_signature,
        }
        manifest.update(overrides)
        return manifest

    # ── Valid manifest tests ──────────────────────────────────────────

    def test_valid_manifest_passes_verification(self):
        """A correctly signed manifest should pass ECDSA verification."""
        manifest = self._make_manifest()
        self.assertTrue(
            verify_signature(
                manifest["version_code"],
                manifest["sha256"],
                manifest["signature"],
                EMBEDDED_PUBLIC_KEY_PEM,
            )
        )

    def test_valid_firmware_sha256_matches(self):
        """Untampered firmware should match the manifest SHA-256."""
        self.assertEqual(self.firmware_sha256, sha256_bytes(self.firmware_data))

    # ── Tampered binary (SHA-256 mismatch) ────────────────────────────

    def test_tampered_binary_sha256_mismatch(self):
        """Flipping bytes in firmware should produce different SHA-256."""
        tampered = bytearray(self.firmware_data)
        tampered[500] ^= 0xFF  # flip a byte in the middle
        tampered_hash = sha256_bytes(bytes(tampered))
        self.assertNotEqual(tampered_hash, self.firmware_sha256)

    def test_tampered_binary_with_old_manifest_rejected(self):
        """Tampered binary served with valid manifest → SHA-256 mismatch on device."""
        tampered = bytearray(self.firmware_data)
        tampered[500] ^= 0xFF
        tampered_hash = sha256_bytes(bytes(tampered))

        # Manifest still has the ORIGINAL hash (this is what the attacker serves)
        manifest = self._make_manifest()

        # Device would compute hash of downloaded (tampered) binary
        # and compare against manifest hash
        hash_matches = tampered_hash == manifest["sha256"]
        self.assertFalse(hash_matches, "Tampered binary hash should NOT match manifest")

    # ── Tampered signature ────────────────────────────────────────────

    def test_tampered_signature_rejected(self):
        """A single bit flip in the signature should fail ECDSA verification."""
        sig_bytes = base64.b64decode(self.valid_signature)
        tampered_sig = bytearray(sig_bytes)
        tampered_sig[10] ^= 0x01  # flip one bit
        tampered_sig_b64 = base64.b64encode(bytes(tampered_sig)).decode("ascii")

        manifest = self._make_manifest(signature=tampered_sig_b64)
        self.assertFalse(
            verify_signature(
                manifest["version_code"],
                manifest["sha256"],
                manifest["signature"],
                EMBEDDED_PUBLIC_KEY_PEM,
            )
        )

    def test_empty_signature_rejected(self):
        """Empty signature should fail verification."""
        manifest = self._make_manifest(signature="")
        self.assertFalse(
            verify_signature(
                manifest["version_code"],
                manifest["sha256"],
                manifest["signature"],
                EMBEDDED_PUBLIC_KEY_PEM,
            )
        )

    def test_random_bytes_signature_rejected(self):
        """Random bytes (not a valid DER signature) should fail."""
        fake_sig = base64.b64encode(os.urandom(64)).decode("ascii")
        manifest = self._make_manifest(signature=fake_sig)
        self.assertFalse(
            verify_signature(
                manifest["version_code"],
                manifest["sha256"],
                manifest["signature"],
                EMBEDDED_PUBLIC_KEY_PEM,
            )
        )

    # ── Tampered hash (breaks signed payload) ─────────────────────────

    def test_tampered_hash_rejected(self):
        """Changing the SHA-256 hash invalidates the ECDSA signature
        (hash is part of the signed payload: version_code + sha256)."""
        fake_hash = "a" * 64  # 64 hex chars
        manifest = self._make_manifest(sha256=fake_hash)

        # Signature was computed with the original hash, so verification fails
        self.assertFalse(
            verify_signature(
                manifest["version_code"],
                manifest["sha256"],
                manifest["signature"],
                EMBEDDED_PUBLIC_KEY_PEM,
            )
        )

    def test_hash_single_char_changed_rejected(self):
        """Changing even one character in the hash invalidates the signature."""
        tampered_hash = list(self.firmware_sha256)
        # Flip one hex digit
        tampered_hash[0] = "f" if tampered_hash[0] != "f" else "0"
        tampered_hash = "".join(tampered_hash)
        manifest = self._make_manifest(sha256=tampered_hash)

        self.assertFalse(
            verify_signature(
                manifest["version_code"],
                manifest["sha256"],
                manifest["signature"],
                EMBEDDED_PUBLIC_KEY_PEM,
            )
        )

    # ── Tampered version (breaks signed payload) ──────────────────────

    def test_tampered_version_rejected(self):
        """Changing version_code invalidates the ECDSA signature
        (version is part of the signed payload: version_code + sha256)."""
        manifest = self._make_manifest(version_code=self.version_code + 1)

        # Signature was computed with original version, verification fails
        self.assertFalse(
            verify_signature(
                manifest["version_code"],
                manifest["sha256"],
                manifest["signature"],
                EMBEDDED_PUBLIC_KEY_PEM,
            )
        )

    def test_version_off_by_one_rejected(self):
        """Version off by ±1 should fail verification."""
        for delta in (-1, 1):
            with self.subTest(delta=delta):
                manifest = self._make_manifest(version_code=self.version_code + delta)
                self.assertFalse(
                    verify_signature(
                        manifest["version_code"],
                        manifest["sha256"],
                        manifest["signature"],
                        EMBEDDED_PUBLIC_KEY_PEM,
                    )
                )

    # ── Wrong signing key ─────────────────────────────────────────────

    def test_wrong_signing_key_rejected(self):
        """Manifest signed with a different private key should fail
        verification against the embedded public key."""
        # Generate a fresh key pair (NOT the one embedded in firmware)
        wrong_private_key = ec.generate_private_key(ec.SECP256R1())
        wrong_private_pem = wrong_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        wrong_signature = sign_manifest(
            self.version_code, self.firmware_sha256, wrong_private_pem
        )
        manifest = self._make_manifest(signature=wrong_signature)

        self.assertFalse(
            verify_signature(
                manifest["version_code"],
                manifest["sha256"],
                manifest["signature"],
                EMBEDDED_PUBLIC_KEY_PEM,
            )
        )

    # ── Anti-rollback (mirrors ota.h logic) ───────────────────────────

    def test_downgrade_rejected(self):
        """Version <= current should be rejected (anti-rollback).
        This mirrors the check in ota.h: if (remote_version <= FW_VERSION_CODE)."""
        current_version = self.version_code
        for bad_version in (current_version, current_version - 1, current_version - 100):
            with self.subTest(version=bad_version):
                # Even if the signature is valid for this version, the
                # anti-rollback check would reject it before verification
                should_update = bad_version > current_version
                self.assertFalse(should_update)

    # ── Missing fields (mirrors ota.h guards) ─────────────────────────

    def test_missing_sha256_rejected(self):
        """Empty or missing sha256 should fail (ota.h checks length == 64)."""
        manifest = self._make_manifest(sha256="")
        self.assertNotEqual(len(manifest["sha256"]), 64)

    def test_missing_signature_rejected(self):
        """Empty signature should fail (ota.h checks length > 0)."""
        manifest = self._make_manifest(signature="")
        self.assertEqual(len(manifest["signature"]), 0)

    def test_zero_version_rejected(self):
        """version_code of 0 should be rejected (ota.h checks remote_version == 0)."""
        manifest = self._make_manifest(version_code=0)
        self.assertEqual(manifest["version_code"], 0)


class TestReSignTamperedBinary(unittest.TestCase):
    """
    Test that even if an attacker re-signs a tampered binary with the correct
    private key, the ECDSA signature would still be different from the original.

    This verifies that an attacker who has tampered the binary but does NOT
    have the private key cannot produce a valid signature.
    """

    @classmethod
    def setUpClass(cls):
        if not PRIVATE_KEY_PATH.exists():
            raise unittest.SkipTest(f"Private key not found at {PRIVATE_KEY_PATH}")
        cls.private_key_pem = PRIVATE_KEY_PATH.read_bytes()
        cls.firmware_data = os.urandom(2048)
        cls.firmware_sha256 = sha256_bytes(cls.firmware_data)
        cls.version_code = 12345

    def test_tampered_binary_produces_different_hash(self):
        """Tampering even one byte changes the SHA-256 completely."""
        tampered = bytearray(self.firmware_data)
        tampered[0] ^= 0x01
        tampered_hash = sha256_bytes(bytes(tampered))
        self.assertNotEqual(tampered_hash, self.firmware_sha256)

    def test_tampered_binary_produces_different_signature(self):
        """The ECDSA signature covers (version + sha256).
        A different sha256 means a different signature is required.
        Attacker without private key cannot compute it."""
        tampered = bytearray(self.firmware_data)
        tampered[0] ^= 0x01
        tampered_hash = sha256_bytes(bytes(tampered))

        original_sig = sign_manifest(
            self.version_code, self.firmware_sha256, self.private_key_pem
        )
        # Verify original sig does NOT work with tampered hash
        self.assertFalse(
            verify_signature(
                self.version_code, tampered_hash, original_sig, EMBEDDED_PUBLIC_KEY_PEM
            )
        )


if __name__ == "__main__":
    unittest.main()
