# Code Signing for LSM-CI Auto-Update

This document describes the Ed25519 code signing implementation for the lsm-ci auto-update mechanism.

## Overview

The lsm-ci system uses automatic code updates where `node_manager.py` pushes updates to `node.py` clients. To prevent a compromised server from pushing malicious code, we implement cryptographic code signing with Ed25519.

## Security Model

**Threat**: A compromised `node_manager.py` server attempts to push malicious code to clients.

**Protection**:
- Private signing key stored OFFLINE (never on server)
- Public verification key embedded in client code
- Clients verify Ed25519 signatures before accepting updates
- Server cannot create valid signatures (only distribute pre-signed files)

**Signed Files**:
- `node.py` - Client daemon
- `testlib.py` - Shared library
- `ci_unit_test.sh` - Test runner script

## Key Management

### Production Keys (CRITICAL - KEEP OFFLINE)

```bash
# Generate production keypair (on secure offline machine)
python3 tools/keygen.py --output certs/code_signing.key

# This generates:
#   certs/code_signing.key  (PRIVATE - NEVER commit, NEVER on server)
#   certs/code_signing.pub  (PUBLIC - reference only)
```

**Private Key Security**:
- Generate on air-gapped machine or secure workstation
- Store on encrypted USB drive or HSM
- NEVER store on production server
- NEVER commit to git
- Keep offline except during signing ceremonies

### Test Keys (for development)

```bash
# Generate test keypair
python3 tools/keygen.py --output certs/test_signing.key --test

# Test keys CAN be committed for CI/development
```

## Initial Deployment (Bootstrap)

The first deployment requires manual steps to establish the trust chain:

### Step 1: Generate Production Keys (Offline Machine)

```bash
# On secure offline machine
cd /path/to/lsm-ci
python3 tools/keygen.py --output certs/code_signing.key

# Output will show public key hex, e.g.:
# a1b2c3d4e5f6... (64 hex characters)
```

### Step 2: Embed Public Key in node.py

Edit `node.py` and update the `CODE_SIGNING_PUBLIC_KEY` constant:

```python
CODE_SIGNING_PUBLIC_KEY = "a1b2c3d4e5f6..."  # Use the hex from Step 1
```

### Step 3: Sign All Files (Offline Machine)

```bash
python3 tools/sign_files.py --key certs/code_signing.key

# This creates signatures.json
```

### Step 4: Verify Signatures

```bash
python3 tools/verify_files.py --key certs/code_signing.pub

# Should show all files as valid
```

### Step 5: Deploy to Server

```bash
scp node.py testlib.py ci_unit_test.sh signatures.json server:/path/to/lsm-ci/
```

### Step 6: Manual Deploy to ALL Clients (ONE TIME ONLY)

```bash
# Deploy signed files to each client manually
for node in node1 node2 node3; do
  scp node.py testlib.py ci_unit_test.sh $node:/path/to/lsm-ci/
  ssh $node "systemctl restart lsm-ci-node"
done
```

After this bootstrap, all future updates are automatic via the signed update mechanism.

## Development Workflow

### Making Code Changes

```bash
# 1. Make code changes
vim node.py

# 2. Test locally with test keys (already signed)
export LSM_CI_DEV_MODE=1
python3 node.py

# 3. For production deployment, sign on secure machine
python3 tools/sign_files.py --key /secure/usb/code_signing.key

# 4. Verify signatures
python3 tools/verify_files.py --key certs/code_signing.pub

# 5. Deploy to server (auto-distributes to all clients)
scp node.py testlib.py ci_unit_test.sh signatures.json server:/path/to/lsm-ci/
```

### Development Mode

Set `LSM_CI_DEV_MODE=1` to use test signing keys:

```bash
export LSM_CI_DEV_MODE=1
python3 node.py
```

This allows testing without production keys.

## Tools

### keygen.py - Generate Ed25519 Keypair

```bash
# Production keys
python3 tools/keygen.py --output certs/code_signing.key

# Test keys
python3 tools/keygen.py --output certs/test_signing.key --test
```

### sign_files.py - Sign Files Offline

```bash
# Sign with production key
python3 tools/sign_files.py --key /secure/usb/code_signing.key

# Sign with test key
python3 tools/sign_files.py --key certs/test_signing.key

# Sign files in different directory
python3 tools/sign_files.py --key certs/code_signing.key --dir /path/to/files
```

Generates `signatures.json`:
```json
{
  "node.py": {
    "sha256": "abc123...",
    "signature": "def456..."
  },
  ...
}
```

### verify_files.py - Verify Signatures

```bash
# Verify with public key file
python3 tools/verify_files.py --key certs/code_signing.pub

# Verify with hex key
python3 tools/verify_files.py --key-hex a1b2c3d4e5f6...

# Verify files in different directory
python3 tools/verify_files.py --key certs/code_signing.pub --dir /path/to/files
```

### test_signature_verification.py - Run Tests

```bash
python3 tools/test_signature_verification.py
```

Tests:
- Valid signatures accepted
- Invalid signatures rejected
- Tampered files rejected
- Missing signatures rejected

## How It Works

### Update Flow

```
[Offline Machine]
  ↓ Sign files with private key
[Server]
  ↓ Distribute signed files (read-only, cannot forge signatures)
[Clients]
  ↓ Verify signatures with embedded public key
  ↓ Accept if valid, reject if invalid
[Client Updated]
```

### Signature Verification (node.py)

When receiving an update:

1. **Phase 1**: Write all files to temp directory
2. **Phase 2**: Verify ALL signatures BEFORE moving ANY files (atomic check)
   - Calculate SHA-256 hash of each file
   - Verify hash matches expected hash
   - Verify Ed25519 signature on hash
   - Reject entire update if ANY signature invalid
3. **Phase 3**: If all signatures valid, move files into place

### Server Update Distribution (testlib.py)

When pushing updates:

1. Load `signatures.json`
2. For each file:
   - Read file content
   - Calculate SHA-256 hash
   - Verify hash matches signature (sanity check)
   - Include hash and signature in update payload
3. Send signed payload to client via RPC

## Cryptographic Details

- **Algorithm**: Ed25519 (Edwards-curve Digital Signature Algorithm)
- **Key Size**: 32 bytes (256 bits)
- **Signature Size**: 64 bytes (512 bits)
- **Hash**: SHA-256 (replaced MD5)
- **Library**: Python `cryptography` package

**Why Ed25519?**
- Modern, secure elliptic curve signatures
- Small keys (32 bytes vs 256 bytes for RSA-2048)
- Fast verification (~0.05ms per file)
- Deterministic signing (safer than probabilistic schemes)
- Immune to timing attacks

## Key Rotation

To rotate keys (recommended annually):

### Step 1: Generate New Key

```bash
python3 tools/keygen.py --output certs/code_signing_new.key
```

### Step 2: Dual-Signature Period

Update `node.py` to accept both old and new keys:

```python
CODE_SIGNING_PUBLIC_KEY = "old_key_hex"
CODE_SIGNING_PUBLIC_KEY_NEW = "new_key_hex"

# In verification code, try both keys
```

Sign with both keys for transition period.

### Step 3: Deploy Update

Deploy update with dual-signature support to all clients.

### Step 4: Switch to New Key Only

After all clients updated (wait 1-2 weeks), remove old key:

```python
CODE_SIGNING_PUBLIC_KEY = "new_key_hex"
```

Sign files with new key only.

### Step 5: Decommission Old Key

Securely destroy old private key.

## Troubleshooting

### "Code signing public key not configured"

The `CODE_SIGNING_PUBLIC_KEY` constant in `node.py` is not set. Update it with your public key hex.

### "Missing SHA-256 hash for node.py"

The `signatures.json` file is missing or invalid. Re-sign files:

```bash
python3 tools/sign_files.py --key certs/code_signing.key
```

### "Invalid signature for node.py"

Possible causes:
1. File modified after signing - re-sign files
2. Wrong public key in `node.py` - verify key matches
3. Corrupted `signatures.json` - re-sign files

### "Hash mismatch for node.py"

File content doesn't match signature. This indicates:
1. File modified after signing - DANGER if you didn't modify it
2. Need to re-sign files after code changes

## Security Considerations

### What This Protects Against

✅ Compromised server pushing malicious code
✅ Man-in-the-middle attacks (defense in depth)
✅ File tampering during transfer
✅ Replay attacks (hash in signature prevents reuse)

### What This Does NOT Protect Against

❌ Compromised private key (requires key rotation)
❌ Compromised client before bootstrap
❌ Social engineering (tricking admin to sign malicious code)
❌ Zero-day vulnerabilities in signed code

### Defense in Depth

Code signing is one layer. Also ensure:
- TLS for network communication
- File system permissions
- Audit logging
- Regular security updates
- Key rotation

## Performance

- **Signature verification**: ~0.15ms total for 3 files
- **Network overhead**: 192 bytes (64 bytes × 3 signatures)
- **Impact**: Negligible - dominated by network I/O

## Files Reference

### New Files

- `tools/keygen.py` - Generate Ed25519 keypairs
- `tools/sign_files.py` - Sign files offline
- `tools/verify_files.py` - Verify signatures
- `tools/test_signature_verification.py` - Test suite
- `signatures.json` - Signature manifest (auto-generated)
- `certs/code_signing.key` - Production private key (OFFLINE ONLY)
- `certs/code_signing.pub` - Production public key
- `certs/test_signing.key` - Test private key (for development)
- `certs/test_signing.pub` - Test public key

### Modified Files

- `node.py` - Client signature verification (lines ~48-60, ~570-670)
- `testlib.py` - Server signature distribution (lines ~59-87, ~554-590, ~800-830)
- `.gitignore` - Exclude production keys

## Quick Reference

```bash
# Generate production key (offline machine)
python3 tools/keygen.py --output /secure/usb/code_signing.key

# Embed public key in node.py (edit CODE_SIGNING_PUBLIC_KEY)

# Sign files (offline machine)
python3 tools/sign_files.py --key /secure/usb/code_signing.key

# Verify signatures
python3 tools/verify_files.py --key certs/code_signing.pub

# Test verification logic
python3 tools/test_signature_verification.py

# Deploy to server
scp node.py testlib.py ci_unit_test.sh signatures.json server:/path/to/lsm-ci/

# Manual bootstrap to clients (ONE TIME)
for node in node1 node2 node3; do
  scp node.py testlib.py ci_unit_test.sh $node:/path/to/lsm-ci/
  ssh $node "systemctl restart lsm-ci-node"
done

# Future updates are automatic after bootstrap
```

## Support

For issues or questions:
- Check troubleshooting section above
- Verify signatures with `verify_files.py`
- Run tests with `test_signature_verification.py`
- Review code in `node.py` (signature verification) and `testlib.py` (signature distribution)
