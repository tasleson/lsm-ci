# Code Signing Quick Start Guide

## For Impatient Admins

This is the TL;DR version. For full details, see `CODE_SIGNING.md`.

## What Is This?

Code signing prevents a compromised server from pushing malicious code to clients. The server can't create valid signatures because the private key is kept offline.

**New**: Both client and server now verify signatures on startup to detect tampering before running!

## Current Status

✅ Implementation complete and tested
⚠️ Using test keys (replace with production keys before deployment)

## Production Deployment (5 Steps)

### 1. Generate Production Keys (Offline Machine)

```bash
python3 tools/keygen.py --output /secure/usb/code_signing.key
```

Copy the hex public key from the output.

### 2. Update node.py

Edit `node.py` and replace the `CODE_SIGNING_PUBLIC_KEY` value:

```python
CODE_SIGNING_PUBLIC_KEY = "your_public_key_hex_here"
```

### 3. Sign Files

```bash
python3 tools/sign_files.py --key /secure/usb/code_signing.key
```

### 4. Verify Signatures

```bash
python3 tools/verify_files.py --key /secure/usb/code_signing.pub
```

### 5. Deploy

```bash
# Deploy to server
scp node.py testlib.py ci_unit_test.sh signatures.json server:/path/to/lsm-ci/

# Bootstrap to ALL clients (ONE TIME ONLY)
for node in node1 node2 node3; do
  scp node.py testlib.py ci_unit_test.sh $node:/path/to/lsm-ci/
  ssh $node "systemctl restart lsm-ci-node"
done
```

**IMPORTANT**: Store `/secure/usb/code_signing.key` offline. Never put it on the server.

## Future Updates

After bootstrap, updates are automatic:

```bash
# 1. Make code changes
vim node.py

# 2. Sign with production key
python3 tools/sign_files.py --key /secure/usb/code_signing.key

# 3. Deploy to server (auto-distributes to clients)
scp node.py testlib.py ci_unit_test.sh signatures.json server:/path/to/lsm-ci/
```

## Helper Scripts

### Interactive Bootstrap
```bash
tools/bootstrap_production.sh
```

### Sign and Deploy in One Step
```bash
tools/sign_and_deploy.sh --key /secure/usb/code_signing.key --server user@host:/path
```

### Check Status
```bash
tools/check_implementation.sh
```

### Verify Signatures
```bash
python3 tools/verify_files.py --key certs/code_signing.pub
```

### Run Tests
```bash
python3 tools/test_signature_verification.py
python3 tools/test_update_flow.py
```

## Troubleshooting

### "Invalid signature for node.py"
File was modified after signing. Re-sign files.

### "Missing signature for node.py"
`signatures.json` is missing or incomplete. Re-sign files.

### "Code signing public key not configured"
`CODE_SIGNING_PUBLIC_KEY` in `node.py` is not set. Update it with your public key hex.

### Clients won't connect to server
Old clients can't talk to new server (RPC protocol changed). Bootstrap all clients.

## Security Checklist

Before production:
- [ ] Production keys generated on offline machine
- [ ] Private key stored on encrypted USB/HSM
- [ ] Private key NOT on production server
- [ ] Private key NOT committed to git
- [ ] Public key embedded in node.py
- [ ] All files signed with production key
- [ ] Signatures verified
- [ ] Test deployment on canary node first

## File Overview

### Tools You'll Use
- `tools/keygen.py` - Generate keys
- `tools/sign_files.py` - Sign files
- `tools/verify_files.py` - Check signatures
- `tools/bootstrap_production.sh` - Interactive setup
- `tools/sign_and_deploy.sh` - Workflow helper

### Important Files
- `signatures.json` - Signature manifest (auto-generated)
- `node.py` - Client (verifies signatures)
- `testlib.py` - Shared code (includes signatures in updates)

### Documentation
- `CODE_SIGNING.md` - Full documentation
- `IMPLEMENTATION_SUMMARY.md` - Technical details
- `STARTUP_VERIFICATION.md` - Startup signature checking
- `CHANGES.md` - What changed
- `QUICK_START.md` - This file

## Breaking Changes

⚠️ **RPC Protocol Change**: Old clients cannot communicate with new server

**Mitigation**: Bootstrap all nodes together during initial deployment

## Key Management

**Private Key**:
- Generate offline
- Store on encrypted USB or HSM
- NEVER on production server
- NEVER committed to git
- Only access during signing

**Public Key**:
- Embedded in `node.py` code
- Safe to share
- Changing requires code update

## Performance Impact

Negligible:
- Signature verification: ~0.15ms per update
- Network overhead: 192 bytes per update

## Testing

All tests passing (7/7):

```bash
# Run all tests
tools/check_implementation.sh
```

## Support

1. Check `CODE_SIGNING.md` troubleshooting section
2. Run `tools/check_implementation.sh`
3. Verify signatures: `python3 tools/verify_files.py --key certs/code_signing.pub`

## One-Liner Reference

```bash
# Generate key
python3 tools/keygen.py -o /secure/usb/code_signing.key

# Sign files
python3 tools/sign_files.py -k /secure/usb/code_signing.key

# Verify
python3 tools/verify_files.py -k /secure/usb/code_signing.pub

# Deploy
scp node.py testlib.py ci_unit_test.sh signatures.json server:/path/

# Bootstrap clients (one time)
for n in node1 node2 node3; do scp node.py testlib.py ci_unit_test.sh $n:/path/; done
```

## That's It!

For more details, see `CODE_SIGNING.md`.
