#!/bin/bash
# Helper script for signing files and deploying to server
#
# Usage: ./sign_and_deploy.sh [--key /path/to/key] [--server user@host:/path]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"

# Default values
KEY_PATH="${KEY_PATH:-/secure/usb/code_signing.key}"
SERVER=""
DRY_RUN=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --key|-k)
            KEY_PATH="$2"
            shift 2
            ;;
        --server|-s)
            SERVER="$2"
            shift 2
            ;;
        --dry-run|-n)
            DRY_RUN=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Sign files and optionally deploy to server"
            echo ""
            echo "Options:"
            echo "  --key, -k PATH       Path to private key (default: /secure/usb/code_signing.key)"
            echo "  --server, -s DEST    Server destination (e.g., user@host:/path/to/lsm-ci)"
            echo "  --dry-run, -n        Show what would be done without doing it"
            echo "  --help, -h           Show this help message"
            echo ""
            echo "Examples:"
            echo "  # Sign only (no deploy)"
            echo "  $0 --key /secure/usb/code_signing.key"
            echo ""
            echo "  # Sign and deploy"
            echo "  $0 --key /secure/usb/code_signing.key --server user@server:/opt/lsm-ci"
            echo ""
            echo "  # Dry run to see what would happen"
            echo "  $0 --key /secure/usb/code_signing.key --server user@server:/opt/lsm-ci --dry-run"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

echo "======================================================================="
echo "Sign and Deploy Workflow"
echo "======================================================================="
echo ""

# Check if key exists
if [[ ! -f "$KEY_PATH" ]]; then
    echo "✗ Error: Private key not found at $KEY_PATH"
    echo ""
    echo "Suggestions:"
    echo "  - Check if key path is correct"
    echo "  - Make sure secure storage is mounted"
    echo "  - Use --key option to specify key location"
    exit 1
fi

echo "Configuration:"
echo "  Private key: $KEY_PATH"
if [[ -n "$SERVER" ]]; then
    echo "  Server: $SERVER"
else
    echo "  Server: (not deploying)"
fi
echo "  Dry run: $DRY_RUN"
echo ""

# Step 1: Sign files
echo "======================================================================="
echo "Step 1: Signing Files"
echo "======================================================================="
echo ""

if [[ "$DRY_RUN" = true ]]; then
    echo "[DRY RUN] Would run: python3 tools/sign_files.py --key $KEY_PATH"
else
    cd "$BASE_DIR"
    python3 tools/sign_files.py --key "$KEY_PATH"
fi

echo ""

# Step 2: Verify signatures
echo "======================================================================="
echo "Step 2: Verifying Signatures"
echo "======================================================================="
echo ""

PUB_KEY_PATH="${KEY_PATH%.key}.pub"

if [[ ! -f "$PUB_KEY_PATH" ]]; then
    echo "⚠ Warning: Public key not found at $PUB_KEY_PATH"
    echo "Skipping verification..."
else
    if [[ "$DRY_RUN" = true ]]; then
        echo "[DRY RUN] Would run: python3 tools/verify_files.py --key $PUB_KEY_PATH"
    else
        cd "$BASE_DIR"
        python3 tools/verify_files.py --key "$PUB_KEY_PATH"
    fi
fi

echo ""

# Step 3: Deploy to server (if specified)
if [[ -n "$SERVER" ]]; then
    echo "======================================================================="
    echo "Step 3: Deploying to Server"
    echo "======================================================================="
    echo ""

    FILES_TO_DEPLOY=(
        "node.py"
        "testlib.py"
        "ci_unit_test.sh"
        "signatures.json"
    )

    echo "Files to deploy:"
    for f in "${FILES_TO_DEPLOY[@]}"; do
        echo "  - $f"
    done
    echo ""

    if [[ "$DRY_RUN" = true ]]; then
        echo "[DRY RUN] Would run:"
        echo "  scp ${FILES_TO_DEPLOY[@]} $SERVER"
    else
        read -p "Deploy to $SERVER? (yes/no) " -r
        if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
            cd "$BASE_DIR"
            scp "${FILES_TO_DEPLOY[@]}" "$SERVER"
            echo ""
            echo "✓ Files deployed successfully!"
            echo ""
            echo "Next steps:"
            echo "  - Files will auto-update to clients on next check"
            echo "  - Monitor client logs for successful updates"
            echo "  - Check for any signature verification errors"
        else
            echo "Deployment cancelled."
        fi
    fi
else
    echo "======================================================================="
    echo "Step 3: Deployment (Skipped)"
    echo "======================================================================="
    echo ""
    echo "No server specified. Files are signed but not deployed."
    echo ""
    echo "To deploy manually:"
    echo "  scp node.py testlib.py ci_unit_test.sh signatures.json user@server:/path/to/lsm-ci/"
    echo ""
    echo "Or run this script with --server option:"
    echo "  $0 --key $KEY_PATH --server user@server:/path/to/lsm-ci"
fi

echo ""
echo "======================================================================="
echo "Complete!"
echo "======================================================================="
echo ""

if [[ "$DRY_RUN" = true ]]; then
    echo "This was a dry run. No changes were made."
    echo "Run without --dry-run to actually sign and deploy."
fi
