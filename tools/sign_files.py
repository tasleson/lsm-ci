#!/usr/bin/env python3
"""
Offline file signing tool for lsm-ci auto-update mechanism.

Signs the three auto-updated files with Ed25519 signatures:
- node.py
- testlib.py
- ci_unit_test.sh

Generates signatures.json containing SHA-256 hashes and signatures.
This tool should be run on a secure offline machine with the private key.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

FILES_TO_SIGN = ['node.py', 'testlib.py', 'ci_unit_test.sh']


def load_private_key(key_path):
    """Load Ed25519 private key from PEM file."""
    key_data = key_path.read_bytes()
    private_key = serialization.load_pem_private_key(key_data, password=None)
    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise ValueError("Key file is not an Ed25519 private key")
    return private_key


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


def sign_file(private_key, file_path):
    """Sign a file with Ed25519 signature."""
    file_hash = hash_file(file_path)
    signature = private_key.sign(file_hash)
    return file_hash.hex(), signature.hex()


def sign_files(key_path, base_dir, output_path):
    """Sign all files and generate signatures.json."""

    # Load private key
    print(f"Loading private key from {key_path}...")
    private_key = load_private_key(key_path)

    # Sign each file
    signatures = {}
    print("\nSigning files:")

    for filename in FILES_TO_SIGN:
        file_path = base_dir / filename

        if not file_path.exists():
            print(f"  ✗ {filename} - NOT FOUND", file=sys.stderr)
            return False

        sha256_hex, signature_hex = sign_file(private_key, file_path)

        signatures[filename] = {
            'sha256': sha256_hex,
            'signature': signature_hex
        }

        file_size = file_path.stat().st_size
        print(
            f"  ✓ {filename:20s} ({file_size:7d} bytes)  {sha256_hex[:16]}...")

    # Write signatures.json
    output_file = output_path or (base_dir / 'signatures.json')
    with open(output_file, 'w') as f:
        json.dump(signatures, f, indent=2)

    print(f"\n✓ Signatures written to {output_file}")
    print(f"\nNext steps:")
    print(f"  1. Deploy signed files to server:")
    print(
        f"     scp {' '.join(FILES_TO_SIGN)} signatures.json server:/path/to/lsm-ci/"
    )
    print(f"  2. For first deployment, manually deploy to all clients")
    print(f"  3. Future updates will auto-deploy via signed update mechanism")

    return True


def main():
    parser = argparse.ArgumentParser(
        description='Sign lsm-ci files for auto-update',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Sign files with production key
  %(prog)s --key /secure/usb/code_signing.key

  # Sign files with test key
  %(prog)s --key certs/test_signing.key

  # Sign files in different directory
  %(prog)s --key certs/code_signing.key --dir /path/to/files
""")
    parser.add_argument('--key',
                        '-k',
                        type=Path,
                        required=True,
                        help='Path to private key file')
    parser.add_argument(
        '--dir',
        '-d',
        type=Path,
        default=Path('.'),
        help=
        'Base directory containing files to sign (default: current directory)')
    parser.add_argument(
        '--output',
        '-o',
        type=Path,
        help='Output path for signatures.json (default: <dir>/signatures.json)'
    )

    args = parser.parse_args()

    # Verify key exists
    if not args.key.exists():
        print(f"Error: Private key not found: {args.key}", file=sys.stderr)
        return 1

    # Verify base directory exists
    if not args.dir.is_dir():
        print(f"Error: Directory not found: {args.dir}", file=sys.stderr)
        return 1

    try:
        success = sign_files(args.key, args.dir, args.output)
        return 0 if success else 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
