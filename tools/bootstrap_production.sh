#!/bin/bash
# Bootstrap script for production code signing deployment
#
# This script guides you through the initial deployment of code signing.
# It should be run ONCE during the initial setup.
#
# SECURITY WARNING: This script will help you generate production keys.
# The private key must be kept OFFLINE and SECURE at all times.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"

echo "======================================================================="
echo "LSM-CI Code Signing Bootstrap"
echo "======================================================================="
echo ""
echo "This script will guide you through the initial deployment of code"
echo "signing for the lsm-ci auto-update mechanism."
echo ""
echo "SECURITY WARNING:"
echo "  - The private key MUST be kept OFFLINE"
echo "  - NEVER commit the private key to git"
echo "  - NEVER store the private key on the production server"
echo "  - Store on encrypted USB or secure offline storage"
echo ""
read -p "Do you want to continue? (yes/no) " -r
if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
    echo "Aborted."
    exit 1
fi

echo ""
echo "======================================================================="
echo "Step 1: Generate Production Keypair"
echo "======================================================================="
echo ""
echo "We will generate an Ed25519 keypair for code signing."
echo ""
read -p "Where should the private key be stored? [/tmp/code_signing.key]: " KEY_PATH
KEY_PATH=${KEY_PATH:-/tmp/code_signing.key}

if [[ -f "$KEY_PATH" ]]; then
    echo "Error: Key already exists at $KEY_PATH"
    read -p "Overwrite? (yes/no) " -r
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        echo "Aborted."
        exit 1
    fi
fi

echo ""
echo "Generating keypair..."
python3 "$SCRIPT_DIR/keygen.py" --output "$KEY_PATH"

PUB_KEY_PATH="${KEY_PATH%.key}.pub"

# Extract public key hex
PUB_KEY_HEX=$(python3 -c "
from cryptography.hazmat.primitives import serialization
with open('$PUB_KEY_PATH', 'rb') as f:
    pub_key = serialization.load_pem_public_key(f.read())
    pub_key_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    print(pub_key_bytes.hex())
")

echo ""
echo "✓ Keypair generated successfully!"
echo "  Private key: $KEY_PATH"
echo "  Public key:  $PUB_KEY_PATH"
echo "  Public key (hex): $PUB_KEY_HEX"
echo ""

echo "======================================================================="
echo "Step 2: Update node.py with Public Key"
echo "======================================================================="
echo ""
echo "We need to embed the public key in node.py"
echo ""
echo "Current public key in node.py will be replaced with:"
echo "  $PUB_KEY_HEX"
echo ""
read -p "Update node.py automatically? (yes/no) " -r

if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
    # Backup node.py
    cp "$BASE_DIR/node.py" "$BASE_DIR/node.py.backup"
    echo "✓ Backed up node.py to node.py.backup"

    # Update CODE_SIGNING_PUBLIC_KEY in node.py
    sed -i "s/^CODE_SIGNING_PUBLIC_KEY = .*/CODE_SIGNING_PUBLIC_KEY = \"$PUB_KEY_HEX\"/" "$BASE_DIR/node.py"
    echo "✓ Updated CODE_SIGNING_PUBLIC_KEY in node.py"
else
    echo ""
    echo "Please manually update node.py:"
    echo "  CODE_SIGNING_PUBLIC_KEY = \"$PUB_KEY_HEX\""
    echo ""
    read -p "Press Enter when done..." -r
fi

echo ""
echo "======================================================================="
echo "Step 3: Sign Files"
echo "======================================================================="
echo ""
echo "Signing node.py, testlib.py, and ci_unit_test.sh..."
python3 "$SCRIPT_DIR/sign_files.py" --key "$KEY_PATH" --dir "$BASE_DIR"

echo ""
echo "======================================================================="
echo "Step 4: Verify Signatures"
echo "======================================================================="
echo ""
python3 "$SCRIPT_DIR/verify_files.py" --key "$PUB_KEY_PATH" --dir "$BASE_DIR"

echo ""
echo "======================================================================="
echo "Step 5: Deployment Instructions"
echo "======================================================================="
echo ""
echo "The following files are now signed and ready for deployment:"
echo "  - node.py (with embedded public key)"
echo "  - testlib.py"
echo "  - ci_unit_test.sh"
echo "  - signatures.json"
echo ""
echo "IMPORTANT: You must now:"
echo ""
echo "1. SECURE THE PRIVATE KEY:"
echo "   - Move $KEY_PATH to secure offline storage"
echo "   - Store on encrypted USB drive or HSM"
echo "   - NEVER store on production server"
echo "   - Command: mv $KEY_PATH /path/to/secure/storage/"
echo ""
echo "2. DEPLOY TO SERVER:"
echo "   - scp node.py testlib.py ci_unit_test.sh signatures.json server:/path/to/lsm-ci/"
echo ""
echo "3. MANUALLY DEPLOY TO ALL CLIENTS (ONE TIME ONLY):"
echo "   - for node in node1 node2 node3; do"
echo "       scp node.py testlib.py ci_unit_test.sh \$node:/path/to/lsm-ci/"
echo "       ssh \$node 'systemctl restart lsm-ci-node'"
echo "     done"
echo ""
echo "4. FUTURE UPDATES:"
echo "   - After this bootstrap, all future updates are automatic"
echo "   - To update code:"
echo "     a) Make changes to files"
echo "     b) Sign with: python3 tools/sign_files.py --key /secure/storage/code_signing.key"
echo "     c) Deploy to server (auto-distributes to clients)"
echo ""
echo "======================================================================="
echo "Bootstrap Complete!"
echo "======================================================================="
echo ""
echo "Remember to:"
echo "  ✓ Move private key to secure offline storage"
echo "  ✓ Deploy signed files to server"
echo "  ✓ Manually deploy to all clients (one time)"
echo "  ✓ Test with one canary client before rolling out to all"
echo ""
