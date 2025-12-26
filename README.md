# Verified Custody SDK - Security Audit

Critical vulnerabilities discovered in `@verified-network/verified-custody@0.4.9`

**Repository:** https://github.com/0xsupremedev/verified-custody-audit  
**Bounty:** Verified Network Christmas Challenge (DoraHacks)  
**Researcher:** 0xsupremedev

## Vulnerability Summary

| Severity | Count | Description |
|----------|-------|-------------|
| CRITICAL | 2 | PIN brute-force, Raw PK storage |
| HIGH | 3 | Weak KDF, Short salt, Non-AEAD encryption |
| MEDIUM | 6 | Timing attack, Case-insensitive hash, No salt, Deterministic vault IDs, Hashed PIN transmission, No key zeroization |

## CRITICAL Vulnerabilities

### CRITICAL #1: Private Key Extraction via PIN Brute-Force
- **CVSS:** 9.1
- **Attack time:** < 2 seconds
- **Root cause:** 4-digit PIN = 10,000 combinations, no key stretching (PBKDF2/Argon2)
- **Impact:** Complete private key recovery from encrypted storage

```
Attack Results:
  Cracked PIN: 7391
  Time elapsed: 1263ms
  Success Rate: 100%
```

### CRITICAL #2: Raw Private Key in Storage
- **CVSS:** 9.8
- **No brute-force required** - pure logic flaw
- **Root cause:** Raw PK stored in `lastPk` during vault creation
- **Impact:** Immediate key theft via malicious extension or race condition

## HIGH Vulnerabilities

| # | Vulnerability | Description |
|---|---------------|-------------|
| 1 | Weak Key Derivation | CryptoJS uses MD5 with 1 iteration (EVP_BytesToKey) |
| 2 | Short Salt | Only 8 bytes (64 bits) vs recommended 16 bytes |
| 3 | Non-AEAD Encryption | AES-CBC without authentication, no integrity check |

## MEDIUM Vulnerabilities

| # | Vulnerability | Description |
|---|---------------|-------------|
| 1 | Timing Side-Channel | 37.6% timing variance enables statistical PIN recovery |
| 2 | Case-Insensitive Hash | `hashTheString` lowercases input, reduces entropy |
| 3 | No Salt in Hash | Deterministic hashing enables rainbow tables |
| 4 | Deterministic Vault IDs | Same email = same vaultId globally, enables enumeration |
| 5 | Hashed PIN Transmission | PIN hash sent in co-signer communications |
| 6 | No Key Zeroization | JS strings immutable, keys persist in heap |

## PoC Files

| File | Description |
|------|-------------|
| `poc-pin-bruteforce.js` | CRITICAL #1 - PIN brute-force attack |
| `poc-raw-pk-storage.js` | CRITICAL #2 - Raw key exposure |
| `poc-attack-chain.js` | Combined attack demonstration |
| `poc-additional-tests.js` | Vault ID enumeration, PIN transmission |
| `comprehensive-vuln-scanner.js` | Full vulnerability scanner |

## Quick Start

```bash
npm install
node poc-pin-bruteforce.js        # Test CRITICAL #1
node poc-raw-pk-storage.js        # Test CRITICAL #2
node poc-attack-chain.js          # Combined attack
node poc-additional-tests.js      # Additional findings
node comprehensive-vuln-scanner.js # Full scan
```

## Reports

- `FINAL_SUBMISSION.md` - Complete vulnerability report
- `SECURITY_AUDIT_REPORT.md` - Technical analysis
- `vulnerability-scan-results.json` - Automated scan output

## Attack Chain

```
+-----------------------------------------------------------+
|                    ATTACK CHAIN                           |
+-----------------------------------------------------------+
|  1. Deterministic Vault ID (email -> hash)                |
|  2. Case-insensitive hash (reduces entropy)               |
|  3. No salt (rainbow tables possible)                     |
|  4. Weak KDF (MD5, 1 iteration)                           |
|  5. 4-digit PIN (10,000 combinations)                     |
|  6. Timing side-channel (37.6% variance)                  |
+-----------------------------------------------------------+
|  RESULT: Full private key recovery in < 2 seconds         |
+-----------------------------------------------------------+
```

## Researcher

- GitHub: 0xsupremedev
- Email: 0xsupremedev@gmail.com

## Disclosure

Submitted via Verified Network Bug Bounty (DoraHacks)
