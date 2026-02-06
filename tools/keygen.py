#!/usr/bin/env python3
"""
Ed25519 keypair generation tool for code signing.

Generates a private/public keypair for signing lsm-ci auto-update files.
The private key should be kept OFFLINE on a secure machine.
The public key is embedded in node.py code.
"""

import argparse
import sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def generate_keypair(output_path, test=False):
    """Generate Ed25519 keypair and save to files."""

    # Generate private key
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Serialize private key
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())

    # Serialize public key
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # Also get raw bytes for embedding in code
    public_raw = public_key.public_bytes(encoding=serialization.Encoding.Raw,
                                         format=serialization.PublicFormat.Raw)

    # Determine output paths
    if output_path.suffix == '.key':
        private_path = output_path
        public_path = output_path.with_suffix('.pub')
    else:
        private_path = output_path / ('test_signing.key'
                                      if test else 'code_signing.key')
        public_path = output_path / ('test_signing.pub'
                                     if test else 'code_signing.pub')

    # Write private key
    private_path.write_bytes(private_bytes)
    private_path.chmod(0o600)  # Secure permissions

    # Write public key
    public_path.write_bytes(public_bytes)

    key_type = "TEST" if test else "PRODUCTION"
    print(f"✓ {key_type} keypair generated:")
    print(f"  Private key: {private_path}")
    print(f"  Public key:  {public_path}")
    print()
    print("Public key (hex) for embedding in node.py:")
    print(f"  {public_raw.hex()}")
    print()

    if not test:
        print("⚠ SECURITY WARNING:")
        print(f"  - Store {private_path} on encrypted USB/secure storage")
        print(f"  - NEVER commit private key to git")
        print(f"  - NEVER store private key on production server")
        print(f"  - Keep OFFLINE except during signing")

    return private_path, public_path, public_raw.hex()


def main():
    parser = argparse.ArgumentParser(
        description='Generate Ed25519 keypair for code signing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate production keypair
  %(prog)s --output certs/code_signing.key

  # Generate test keypair for development
  %(prog)s --output certs/test_signing.key --test

  # Generate in a directory
  %(prog)s --output certs/
""")
    parser.add_argument(
        '--output',
        '-o',
        type=Path,
        default=Path('certs/code_signing.key'),
        help='Output path for private key (default: certs/code_signing.key)')
    parser.add_argument('--test',
                        action='store_true',
                        help='Generate test keypair (for development/CI)')

    args = parser.parse_args()

    # Create parent directory if needed
    if args.output.suffix == '.key':
        args.output.parent.mkdir(parents=True, exist_ok=True)
    else:
        args.output.mkdir(parents=True, exist_ok=True)

    try:
        generate_keypair(args.output, args.test)
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
