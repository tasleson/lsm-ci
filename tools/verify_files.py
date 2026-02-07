#!/usr/bin/env python3
"""
Standalone signature verification tool for lsm-ci files.

Verifies that files match their signatures in signatures.json.
Useful for testing and debugging the signing/verification process.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

FILES_TO_VERIFY = ['node.py', 'testlib.py', 'ci_unit_test.sh']


def load_public_key(key_path):
    """Load Ed25519 public key from PEM file."""
    key_data = key_path.read_bytes()
    public_key = serialization.load_pem_public_key(key_data)
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise ValueError("Key file is not an Ed25519 public key")
    return public_key


def load_public_key_from_hex(hex_string):
    """Load Ed25519 public key from hex string."""
    key_bytes = bytes.fromhex(hex_string)
    return ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)


def hash_file(file_path):
    """Calculate SHA-256 hash of file."""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.digest()


def verify_file(public_key, file_path, expected_hash, signature):
    """Verify file signature."""
    # Calculate actual hash
    actual_hash = hash_file(file_path)

    # Check if hash matches
    if actual_hash.hex() != expected_hash:
        return False, "Hash mismatch"

    # Verify signature
    try:
        public_key.verify(bytes.fromhex(signature), actual_hash)
        return True, "Valid"
    except Exception as e:
        return False, f"Invalid signature: {e}"


def verify_files(public_key, base_dir, signatures_path):
    """Verify all files against signatures.json."""

    # Load signatures
    if not signatures_path.exists():
        print(f"Error: Signatures file not found: {signatures_path}",
              file=sys.stderr)
        return False

    with open(signatures_path) as f:
        signatures = json.load(f)

    # Verify each file
    print("Verifying files:\n")
    all_valid = True

    for filename in FILES_TO_VERIFY:
        file_path = base_dir / filename

        if not file_path.exists():
            print(f"  ✗ {filename:20s} - FILE NOT FOUND")
            all_valid = False
            continue

        if filename not in signatures:
            print(f"  ✗ {filename:20s} - NO SIGNATURE")
            all_valid = False
            continue

        sig_data = signatures[filename]
        expected_hash = sig_data['sha256']
        signature = sig_data['signature']

        valid, message = verify_file(public_key, file_path, expected_hash,
                                     signature)

        status = "✓" if valid else "✗"
        file_size = file_path.stat().st_size
        print(f"  {status} {filename:20s} ({file_size:7d} bytes)  {message}")

        if not valid:
            all_valid = False

    print()
    if all_valid:
        print("✓ All signatures valid")
    else:
        print("✗ Some signatures invalid or files missing")

    return all_valid


def main():
    parser = argparse.ArgumentParser(
        description='Verify lsm-ci file signatures',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Verify with public key file
  %(prog)s --key certs/code_signing.pub

  # Verify with hex-encoded public key
  %(prog)s --key-hex a1b2c3d4...

  # Verify files in different directory
  %(prog)s --key certs/code_signing.pub --dir /path/to/files
""")

    key_group = parser.add_mutually_exclusive_group(required=True)
    key_group.add_argument('--key',
                           '-k',
                           type=Path,
                           help='Path to public key file (.pub)')
    key_group.add_argument('--key-hex',
                           type=str,
                           help='Public key as hex string')

    parser.add_argument(
        '--dir',
        '-d',
        type=Path,
        default=Path('.'),
        help=
        'Base directory containing files to verify (default: current directory)'
    )
    parser.add_argument(
        '--signatures',
        '-s',
        type=Path,
        help='Path to signatures.json (default: <dir>/signatures.json)')

    args = parser.parse_args()

    # Load public key
    try:
        if args.key:
            if not args.key.exists():
                print(f"Error: Public key not found: {args.key}",
                      file=sys.stderr)
                return 1
            public_key = load_public_key(args.key)
        else:
            public_key = load_public_key_from_hex(args.key_hex)
    except Exception as e:
        print(f"Error loading public key: {e}", file=sys.stderr)
        return 1

    # Verify base directory exists
    if not args.dir.is_dir():
        print(f"Error: Directory not found: {args.dir}", file=sys.stderr)
        return 1

    # Determine signatures path
    signatures_path = args.signatures or (args.dir / 'signatures.json')

    try:
        success = verify_files(public_key, args.dir, signatures_path)
        return 0 if success else 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
