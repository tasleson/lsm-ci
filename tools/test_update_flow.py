#!/usr/bin/env python3
"""
Integration test for the complete update flow.

Tests the full signature verification flow:
1. Server loads signatures.json
2. Server prepares update payload with signatures
3. Client receives update payload
4. Client verifies signatures
5. Client accepts/rejects update

This simulates the RPC flow without actually running the server/client.
"""

import sys
import os
import json
import tempfile
import shutil
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import testlib


def simulate_server_prepare_update(files):
    """
    Simulate server preparing an update (testlib.Node.update_files logic).

    Returns: List of file data dicts with signatures
    """
    # Load signatures.json
    sig_file = Path(__file__).parent.parent / 'signatures.json'
    with open(sig_file) as f:
        signatures = json.load(f)

    pushed_files = []

    for f in files:
        fn = Path(__file__).parent.parent / f
        sha256_hash, data = testlib.file_sha256_and_data(str(fn))

        if f not in signatures:
            print(f"✗ Server: No signature found for {f}")
            return None

        sig_data = signatures[f]
        expected_hash = sig_data['sha256']
        signature = sig_data['signature']

        # Sanity check
        if sha256_hash != expected_hash:
            print(f"✗ Server: Hash mismatch for {f}")
            return None

        pushed_files.append(
            dict(fn=f, sha256=sha256_hash, signature=signature, data=data))

    return pushed_files


def simulate_client_verify_update(file_data):
    """
    Simulate client verifying and installing update (node.Cmds._update_files logic).

    Returns: (success, error_message)
    """
    from cryptography.hazmat.primitives.asymmetric import ed25519

    # Get the public key (test key for this test)
    pub_key_hex = "e06d6667183e3a2e6083a1cb869c66fc13a2c55d3a4e9d3a25620e2e7dd32f56"
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(pub_key_hex))

    # Create temp directory
    td = tempfile.mkdtemp()

    try:
        tmp_files_data = []

        # Phase 1: Write files to temp
        for i in file_data:
            fn = i["fn"]
            data = i["data"]
            sha256_hash = i.get("sha256")
            signature = i.get("signature")

            if not sha256_hash:
                return False, f"Missing SHA-256 hash for {fn}"

            if not signature:
                return False, f"Missing signature for {fn}"

            tmp_file = os.path.join(td, fn)
            with open(tmp_file, "w") as t:
                t.write(data)

            tmp_files_data.append({
                'fn': fn,
                'tmp_file': tmp_file,
                'expected_hash': sha256_hash,
                'signature': signature
            })

        # Phase 2: Verify ALL signatures
        for item in tmp_files_data:
            fn = item['fn']
            tmp_file = item['tmp_file']
            expected_hash = item['expected_hash']
            signature = item['signature']

            # Calculate actual hash
            actual_hash = testlib.file_sha256(tmp_file)

            # Verify hash
            if actual_hash != expected_hash:
                return False, f"Hash mismatch for {fn}"

            # Verify signature
            try:
                hash_bytes = bytes.fromhex(expected_hash)
                sig_bytes = bytes.fromhex(signature)
                public_key.verify(sig_bytes, hash_bytes)
            except Exception as e:
                return False, f"Invalid signature for {fn}: {e}"

        # All signatures valid
        return True, "All signatures verified successfully"

    finally:
        shutil.rmtree(td)


def test_valid_update_flow():
    """Test the complete update flow with valid signatures."""
    print("\n[TEST] Complete update flow with valid signatures...")

    files = ["node.py", "testlib.py", "ci_unit_test.sh"]

    # Step 1: Server prepares update
    print("  → Server preparing update...")
    file_data = simulate_server_prepare_update(files)

    if not file_data:
        print("  ✗ FAILED: Server could not prepare update")
        return False

    print(f"  → Server prepared {len(file_data)} files with signatures")

    # Step 2: Client verifies and accepts update
    print("  → Client verifying signatures...")
    success, message = simulate_client_verify_update(file_data)

    if not success:
        print(f"  ✗ FAILED: {message}")
        return False

    print(f"  ✓ PASSED: {message}")
    return True


def test_tampered_update_rejection():
    """Test that tampered updates are rejected."""
    print("\n[TEST] Reject tampered update...")

    files = ["node.py"]

    # Step 1: Server prepares update
    file_data = simulate_server_prepare_update(files)

    if not file_data:
        print("  ✗ FAILED: Server could not prepare update")
        return False

    # Step 2: Tamper with the data
    print("  → Tampering with file data...")
    file_data[0]['data'] = "# This is malicious code\n"

    # Step 3: Client should reject
    print("  → Client verifying signatures...")
    success, message = simulate_client_verify_update(file_data)

    if success:
        print("  ✗ FAILED: Tampered update was accepted!")
        return False

    print(f"  ✓ PASSED: Tampered update rejected - {message}")
    return True


def test_invalid_signature_rejection():
    """Test that invalid signatures are rejected."""
    print("\n[TEST] Reject invalid signature...")

    files = ["node.py"]

    # Step 1: Server prepares update
    file_data = simulate_server_prepare_update(files)

    if not file_data:
        print("  ✗ FAILED: Server could not prepare update")
        return False

    # Step 2: Replace signature with invalid one
    print("  → Replacing signature with invalid signature...")
    file_data[0]['signature'] = "00" * 64

    # Step 3: Client should reject
    print("  → Client verifying signatures...")
    success, message = simulate_client_verify_update(file_data)

    if success:
        print("  ✗ FAILED: Invalid signature was accepted!")
        return False

    print(f"  ✓ PASSED: Invalid signature rejected - {message}")
    return True


def main():
    """Run all integration tests."""
    print("=" * 60)
    print("Code Signing Integration Tests (Full Update Flow)")
    print("=" * 60)

    tests = [
        test_valid_update_flow,
        test_tampered_update_rejection,
        test_invalid_signature_rejection,
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
