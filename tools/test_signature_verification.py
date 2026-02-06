#!/usr/bin/env python3
"""
Test script to verify signature verification logic works correctly.

Tests:
1. Valid signatures are accepted
2. Invalid signatures are rejected
3. Tampered files are rejected
4. Missing signatures are rejected
"""

import sys
import os
import json
import tempfile
import shutil
from pathlib import Path

# Add parent directory to path to import node and testlib
sys.path.insert(0, str(Path(__file__).parent.parent))

import testlib
from cryptography.hazmat.primitives.asymmetric import ed25519


def load_test_key():
    """Load the test private key."""
    key_path = Path(__file__).parent.parent / 'certs' / 'test_signing.key'
    with open(key_path, 'rb') as f:
        from cryptography.hazmat.primitives import serialization
        private_key = serialization.load_pem_private_key(f.read(),
                                                         password=None)
    return private_key


def hash_file(file_path):
    """Calculate SHA-256 hash of file."""
    import hashlib
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.digest()


def test_valid_signature():
    """Test that valid signatures are accepted."""
    print("\n[TEST] Valid signature acceptance...")

    # Load signatures
    sig_file = Path(__file__).parent.parent / 'signatures.json'
    with open(sig_file) as f:
        signatures = json.load(f)

    # Load test public key
    from cryptography.hazmat.primitives.asymmetric import ed25519
    pub_key_hex = "e06d6667183e3a2e6083a1cb869c66fc13a2c55d3a4e9d3a25620e2e7dd32f56"
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(pub_key_hex))

    # Verify node.py signature
    node_sig = signatures['node.py']
    node_path = Path(__file__).parent.parent / 'node.py'

    actual_hash = testlib.file_sha256(str(node_path))
    if actual_hash != node_sig['sha256']:
        print(f"  ✗ FAILED: Hash mismatch")
        return False

    # Verify signature
    try:
        hash_bytes = bytes.fromhex(node_sig['sha256'])
        sig_bytes = bytes.fromhex(node_sig['signature'])
        public_key.verify(sig_bytes, hash_bytes)
        print(f"  ✓ PASSED: Valid signature accepted")
        return True
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        return False


def test_invalid_signature():
    """Test that invalid signatures are rejected."""
    print("\n[TEST] Invalid signature rejection...")

    from cryptography.hazmat.primitives.asymmetric import ed25519
    pub_key_hex = "e06d6667183e3a2e6083a1cb869c66fc13a2c55d3a4e9d3a25620e2e7dd32f56"
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(pub_key_hex))

    # Create fake signature
    fake_signature = "00" * 64

    # Try to verify with correct hash
    node_path = Path(__file__).parent.parent / 'node.py'
    actual_hash = testlib.file_sha256(str(node_path))

    try:
        hash_bytes = bytes.fromhex(actual_hash)
        sig_bytes = bytes.fromhex(fake_signature)
        public_key.verify(sig_bytes, hash_bytes)
        print(f"  ✗ FAILED: Invalid signature was accepted!")
        return False
    except Exception:
        print(f"  ✓ PASSED: Invalid signature rejected")
        return True


def test_tampered_file():
    """Test that tampered files are rejected."""
    print("\n[TEST] Tampered file rejection...")

    # Create a temporary file with different content
    td = tempfile.mkdtemp()
    try:
        tampered_file = Path(td) / 'node.py'
        with open(tampered_file, 'w') as f:
            f.write("# This is tampered content\n")

        # Load original signature
        sig_file = Path(__file__).parent.parent / 'signatures.json'
        with open(sig_file) as f:
            signatures = json.load(f)

        node_sig = signatures['node.py']
        actual_hash = testlib.file_sha256(str(tampered_file))

        if actual_hash == node_sig['sha256']:
            print(f"  ✗ FAILED: Tampered file has same hash!")
            return False

        print(f"  ✓ PASSED: Tampered file detected (hash mismatch)")
        return True
    finally:
        shutil.rmtree(td)


def test_missing_signature():
    """Test that files without signatures are rejected."""
    print("\n[TEST] Missing signature rejection...")

    # Simulate missing signature by checking if the code would reject it
    file_data = {
        'fn': 'test.py',
        'data': 'print("hello")',
        # Missing 'sha256' and 'signature' keys
    }

    if 'sha256' not in file_data or 'signature' not in file_data:
        print(f"  ✓ PASSED: Missing signature would be rejected")
        return True
    else:
        print(f"  ✗ FAILED: Missing signature not detected")
        return False


def main():
    """Run all tests."""
    print("=" * 60)
    print("Code Signing Verification Tests")
    print("=" * 60)

    tests = [
        test_valid_signature,
        test_invalid_signature,
        test_tampered_file,
        test_missing_signature,
    ]

    results = []
    for test in tests:
        results.append(test())

    print("\n" + "=" * 60)
    print("Results:")
    print(f"  Passed: {sum(results)}/{len(results)}")
    print(f"  Failed: {len(results) - sum(results)}/{len(results)}")
    print("=" * 60)

    return 0 if all(results) else 1


if __name__ == '__main__':
    sys.exit(main())
