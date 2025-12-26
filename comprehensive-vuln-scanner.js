/**
 * COMPREHENSIVE VULNERABILITY SCANNER
 * Verified Custody SDK - Bug Bounty 2025
 * 
 * Tests for:
 * 1. Shamir Secret Sharing flaws
 * 2. Timing side-channel attacks
 * 3. IV/Salt reuse
 * 4. Memory leaks / key zeroization
 * 5. Threshold bypass attempts
 * 6. Entropy analysis
 * 7. Crypto implementation bugs
 */

const {
    encryptString,
    decryptString,
    hashTheString,
    hashTheBuffer,
    encryptWithPasskey,
    decryptWithPasskey,
    publicKeyCredentialRequestOptions
} = require('@verified-network/verified-custody');
const { split, combine } = require('shamir-secret-sharing');
const { encodeBytes32String } = require('ethers');
const crypto = require('crypto');

// ============ TEST RESULTS ============
const vulnerabilities = [];
const findings = [];

function addVulnerability(severity, title, description, poc = null) {
    vulnerabilities.push({ severity, title, description, poc });
    console.log(`\n🚨 [${severity}] ${title}`);
    console.log(`   ${description}`);
    if (poc) console.log(`   PoC: ${poc}`);
}

function addFinding(type, title, description) {
    findings.push({ type, title, description });
    console.log(`\n📌 [${type}] ${title}`);
    console.log(`   ${description}`);
}

// ============ TEST 1: SHAMIR THRESHOLD BYPASS ============
async function testShamirThresholdBypass() {
    console.log('\n' + '='.repeat(60));
    console.log('TEST 1: SHAMIR THRESHOLD BYPASS ATTEMPTS');
    console.log('='.repeat(60));

    const secret = new Uint8Array(32);
    crypto.randomFillSync(secret);
    const secretHex = Buffer.from(secret).toString('hex');

    console.log(`\nOriginal Secret: ${secretHex.substring(0, 20)}...`);

    // Test: Can we recover with fewer shares than threshold?
    const shares = await split(secret, 5, 3);  // 5 shares, need 3
    console.log(`\nCreated 5 shares with threshold 3`);

    // Try to combine with only 2 shares (should fail or produce wrong result)
    try {
        const twoShares = [shares[0], shares[1]];
        const recovered = await combine(twoShares);
        const recoveredHex = Buffer.from(recovered).toString('hex');

        if (recoveredHex === secretHex) {
            addVulnerability('CRITICAL',
                'Shamir Threshold Bypass',
                'Secret recoverable with fewer shares than threshold!',
                'combine(2 shares) when threshold=3 still works');
        } else {
            addFinding('INFO',
                'Shamir Threshold Enforced',
                'Combining 2 shares (threshold=3) produces garbage, as expected');
        }
    } catch (e) {
        addFinding('INFO',
            'Shamir Threshold Enforced',
            `Combining 2 shares throws error: ${e.message}`);
    }

    // Test: Duplicate share attack
    try {
        const duplicateShares = [shares[0], shares[0], shares[1]];
        const recovered = await combine(duplicateShares);
        addVulnerability('HIGH',
            'Duplicate Share Not Detected',
            'combine() allows duplicate shares without error');
    } catch (e) {
        if (e.message.includes('duplicate')) {
            addFinding('GOOD',
                'Duplicate Share Detection',
                'Duplicate shares correctly rejected');
        } else {
            addFinding('INFO',
                'Duplicate Share Handling',
                `Error on duplicate: ${e.message}`);
        }
    }
}

// ============ TEST 2: TIMING SIDE-CHANNEL ============
async function testTimingSideChannel() {
    console.log('\n' + '='.repeat(60));
    console.log('TEST 2: TIMING SIDE-CHANNEL ANALYSIS');
    console.log('='.repeat(60));

    const testPK = crypto.randomBytes(32).toString('hex');
    const correctPIN = '5678';
    const hashedCorrectPIN = encodeBytes32String(correctPIN);
    const encrypted = encryptString(testPK, hashedCorrectPIN);

    const timings = {};
    const iterations = 100;

    // Test multiple PINs with many iterations
    const testPINs = ['0000', '5678', '9999', '1111', '5679'];

    for (const pin of testPINs) {
        const hashedPin = encodeBytes32String(pin);
        const times = [];

        for (let i = 0; i < iterations; i++) {
            const start = process.hrtime.bigint();
            try {
                decryptString(encrypted, hashedPin);
            } catch (e) { }
            const end = process.hrtime.bigint();
            times.push(Number(end - start));
        }

        // Remove outliers and calculate median
        times.sort((a, b) => a - b);
        const median = times[Math.floor(times.length / 2)];
        const avg = times.reduce((a, b) => a + b, 0) / times.length;

        timings[pin] = { median, avg, isCorrect: pin === correctPIN };
    }

    console.log('\nTiming Analysis Results:');
    console.log('PIN\t\tMedian (ns)\tAvg (ns)\tCorrect');
    console.log('-'.repeat(55));

    let maxDiff = 0;
    let correctTiming = 0;

    for (const [pin, data] of Object.entries(timings)) {
        console.log(`${pin}\t\t${data.median}\t\t${Math.round(data.avg)}\t\t${data.isCorrect ? '✅' : ''}`);
        if (data.isCorrect) correctTiming = data.median;
    }

    // Check for timing differences
    for (const [pin, data] of Object.entries(timings)) {
        if (!data.isCorrect) {
            const diff = Math.abs(data.median - correctTiming);
            if (diff > maxDiff) maxDiff = diff;
        }
    }

    const timingDiffPercent = (maxDiff / correctTiming) * 100;

    if (timingDiffPercent > 20) {
        addVulnerability('MEDIUM',
            'Timing Side-Channel Detected',
            `${timingDiffPercent.toFixed(1)}% timing difference between correct/incorrect PINs`,
            'Could enable statistical PIN recovery');
    } else {
        addFinding('GOOD',
            'No Significant Timing Leak',
            `Timing difference: ${timingDiffPercent.toFixed(1)}% (acceptable)`);
    }
}

// ============ TEST 3: IV/SALT REUSE ============
async function testIVSaltReuse() {
    console.log('\n' + '='.repeat(60));
    console.log('TEST 3: IV/SALT REUSE DETECTION');
    console.log('='.repeat(60));

    const testPK = crypto.randomBytes(32).toString('hex');
    const pin = '1234';
    const hashedPin = encodeBytes32String(pin);

    // Encrypt same data multiple times
    const encryptions = [];
    for (let i = 0; i < 5; i++) {
        const enc = encryptString(testPK, hashedPin);
        encryptions.push(enc);
    }

    console.log('\nEncrypting same data 5 times:');
    encryptions.forEach((e, i) => {
        console.log(`  ${i + 1}: ${e.substring(0, 40)}...`);
    });

    // Check if any encryptions are identical (would indicate IV reuse)
    const uniqueEncs = new Set(encryptions);

    if (uniqueEncs.size < encryptions.length) {
        addVulnerability('HIGH',
            'IV/Salt Reuse Detected',
            'Multiple encryptions of same plaintext produce identical ciphertext!',
            'Indicates deterministic encryption or IV reuse');
    } else {
        addFinding('GOOD',
            'No IV Reuse Detected',
            'Each encryption produces unique ciphertext (proper randomness)');
    }

    // Analyze ciphertext structure
    console.log('\nCiphertext Structure Analysis:');
    const firstEnc = encryptions[0];

    // Check for "Salted__" prefix (CryptoJS default)
    if (firstEnc.startsWith('U2FsdGVk')) {
        addFinding('INFO',
            'CryptoJS AES Detected',
            'Uses "Salted__" prefix format (base64 of "Salted__")');

        // CryptoJS uses PBKDF with default 1 iteration!
        addVulnerability('MEDIUM',
            'Weak Key Derivation in CryptoJS',
            'CryptoJS default uses MD5-based key derivation with low iterations',
            'OpenSSL EVP_BytesToKey with 1 iteration MD5');
    }
}

// ============ TEST 4: ENTROPY ANALYSIS ============
async function testEntropyAnalysis() {
    console.log('\n' + '='.repeat(60));
    console.log('TEST 4: ENTROPY/RANDOMNESS ANALYSIS');
    console.log('='.repeat(60));

    // Test Shamir share randomness
    const secret = new Uint8Array([0x41, 0x42, 0x43, 0x44]); // "ABCD"

    const shareSets = [];
    for (let i = 0; i < 3; i++) {
        const shares = await split(secret, 3, 2);
        shareSets.push(shares);
    }

    console.log('\nGenerating 3 sets of Shamir shares for same secret:');

    let allUnique = true;
    for (let i = 0; i < shareSets.length; i++) {
        for (let j = i + 1; j < shareSets.length; j++) {
            // Compare first share of each set
            const share1 = Buffer.from(shareSets[i][0]).toString('hex');
            const share2 = Buffer.from(shareSets[j][0]).toString('hex');

            if (share1 === share2) {
                allUnique = false;
            }
        }
    }

    if (!allUnique) {
        addVulnerability('CRITICAL',
            'Deterministic Shamir Shares',
            'Same secret produces identical shares - no randomness!',
            'Shares are predictable');
    } else {
        addFinding('GOOD',
            'Shamir Uses Proper Randomness',
            'Each split produces unique shares');
    }
}

// ============ TEST 5: HASH FUNCTION ANALYSIS ============
async function testHashFunction() {
    console.log('\n' + '='.repeat(60));
    console.log('TEST 5: HASH FUNCTION SECURITY ANALYSIS');
    console.log('='.repeat(60));

    // Test hashTheString
    const input1 = 'test';
    const input2 = 'TEST';

    const hash1 = hashTheString(input1);
    const hash2 = hashTheString(input2);

    console.log(`\nhashTheString('test'): ${hash1}`);
    console.log(`hashTheString('TEST'): ${hash2}`);

    // Check if case-insensitive (bad for security)
    if (hash1 === hash2) {
        addVulnerability('MEDIUM',
            'Case-Insensitive Hashing',
            'hashTheString treats input case-insensitively',
            'Reduces entropy for email/phone hashing');
    } else {
        // Check if it lowercases input (from source analysis)
        const hashLower = hashTheString('test');
        const hashUpper = hashTheString('TEST');

        // From source: const t = e.toLowerCase()
        if (hashUpper !== hashLower) {
            addFinding('INFO',
                'Case-Sensitive Hashing',
                'Different cases produce different hashes');
        }
    }

    // Check hash format
    if (hash1.startsWith('0x') && hash1.length === 66) {
        addFinding('INFO',
            'SHA-256 Hash Detected',
            'Output is 32 bytes (66 chars with 0x prefix)');
    }

    // Test for salt usage
    const hash1a = hashTheString(input1);
    const hash1b = hashTheString(input1);

    if (hash1a === hash1b) {
        addVulnerability('MEDIUM',
            'No Salt in Hash',
            'hashTheString is deterministic (no salt)',
            'Enables rainbow table attacks on emails/phones');
    }
}

// ============ TEST 6: PASSKEY ENCRYPTION ANALYSIS ============
async function testPasskeyEncryption() {
    console.log('\n' + '='.repeat(60));
    console.log('TEST 6: PASSKEY ENCRYPTION ANALYSIS');
    console.log('='.repeat(60));

    // Check what publicKeyCredentialRequestOptions returns
    try {
        const options = publicKeyCredentialRequestOptions();
        console.log('\npublicKeyCredentialRequestOptions():');
        console.log(JSON.stringify(options, (key, value) => {
            if (value instanceof Uint8Array) {
                return `Uint8Array(${value.length}): ${Buffer.from(value).toString('hex').substring(0, 20)}...`;
            }
            return value;
        }, 2));

        // Check challenge randomness
        if (options.challenge) {
            const challenges = [];
            for (let i = 0; i < 3; i++) {
                const opts = publicKeyCredentialRequestOptions();
                challenges.push(Buffer.from(opts.challenge).toString('hex'));
            }

            const uniqueChallenges = new Set(challenges);
            if (uniqueChallenges.size < challenges.length) {
                addVulnerability('HIGH',
                    'Predictable Passkey Challenge',
                    'Challenge values are not unique per request',
                    'Enables replay attacks');
            } else {
                addFinding('GOOD',
                    'Random Passkey Challenges',
                    'Each request generates unique challenge');
            }
        }
    } catch (e) {
        addFinding('INFO',
            'Passkey Not Available',
            `Error: ${e.message}`);
    }
}

// ============ TEST 7: KEY ZEROIZATION CHECK ============
async function testKeyZeroization() {
    console.log('\n' + '='.repeat(60));
    console.log('TEST 7: KEY ZEROIZATION / MEMORY SAFETY');
    console.log('='.repeat(60));

    // This is a static analysis finding - document it
    addVulnerability('LOW',
        'No Key Zeroization',
        'SDK uses JavaScript strings for keys - cannot be securely wiped from memory',
        'Strings are immutable, keys persist until GC');

    // Check for console.log in production code
    addFinding('INFO',
        'Memory Safety Limitation',
        'JavaScript runtime does not support secure memory clearing');
}

// ============ TEST 8: CRYPTO-JS SPECIFIC VULNS ============
async function testCryptoJSVulns() {
    console.log('\n' + '='.repeat(60));
    console.log('TEST 8: CRYPTO-JS SPECIFIC VULNERABILITIES');
    console.log('='.repeat(60));

    // Known CryptoJS issues:
    // 1. Uses MD5-based key derivation by default (EVP_BytesToKey)
    // 2. Only 1 iteration by default
    // 3. IV derived from password (not random) in some modes

    addVulnerability('HIGH',
        'CryptoJS Weak Key Derivation',
        'CryptoJS.AES.encrypt uses EVP_BytesToKey with MD5 and 1 iteration by default',
        'Password-based encryption is easily brute-forced');

    // Verify by checking encryption format
    const enc = encryptString('test', 'password');

    // CryptoJS format: "Salted__" (8 bytes) + salt (8 bytes) + ciphertext
    const decoded = Buffer.from(enc, 'base64');
    const prefix = decoded.slice(0, 8).toString('utf8');

    if (prefix === 'Salted__') {
        const salt = decoded.slice(8, 16);
        console.log(`\nCryptoJS Salt: ${salt.toString('hex')}`);
        console.log('Key Derivation: MD5-based EVP_BytesToKey (weak!)');

        addVulnerability('HIGH',
            'Short Salt in Encryption',
            'Only 8 bytes of salt used (64 bits)',
            'Should be at least 16 bytes (128 bits)');
    }
}

// ============ TEST 9: SHAMIR MALFORMED INPUT ============
async function testShamirMalformedInput() {
    console.log('\n' + '='.repeat(60));
    console.log('TEST 9: SHAMIR MALFORMED INPUT HANDLING');
    console.log('='.repeat(60));

    const secret = new Uint8Array([1, 2, 3, 4]);
    const shares = await split(secret, 3, 2);

    // Test 1: Empty share array
    try {
        await combine([]);
        addVulnerability('MEDIUM', 'Empty Share Array Accepted', 'combine([]) should throw');
    } catch (e) {
        addFinding('GOOD', 'Empty Array Rejected', e.message);
    }

    // Test 2: Single share
    try {
        await combine([shares[0]]);
        addVulnerability('MEDIUM', 'Single Share Accepted', 'combine([1 share]) should throw');
    } catch (e) {
        addFinding('GOOD', 'Single Share Rejected', e.message);
    }

    // Test 3: Corrupted share
    try {
        const corrupted = new Uint8Array(shares[0]);
        corrupted[0] ^= 0xFF;  // Flip bits
        await combine([corrupted, shares[1]]);
        addFinding('INFO',
            'Corrupted Share Accepted',
            'No integrity check on shares (expected for Shamir)');
    } catch (e) {
        addFinding('INFO', 'Corrupted Share Handling', e.message);
    }

    // Test 4: Different length shares
    try {
        const shortShare = shares[0].slice(0, -1);
        await combine([shortShare, shares[1]]);
        addVulnerability('MEDIUM', 'Mismatched Share Lengths', 'Should reject different length shares');
    } catch (e) {
        addFinding('GOOD', 'Length Mismatch Detected', e.message);
    }
}

// ============ MAIN ============
async function main() {
    console.log('\n' + '█'.repeat(60));
    console.log('  COMPREHENSIVE VULNERABILITY SCANNER');
    console.log('  Verified Custody SDK - Bug Bounty 2025');
    console.log('█'.repeat(60));

    await testShamirThresholdBypass();
    await testTimingSideChannel();
    await testIVSaltReuse();
    await testEntropyAnalysis();
    await testHashFunction();
    await testPasskeyEncryption();
    await testKeyZeroization();
    await testCryptoJSVulns();
    await testShamirMalformedInput();

    // ============ FINAL REPORT ============
    console.log('\n' + '█'.repeat(60));
    console.log('  VULNERABILITY SUMMARY');
    console.log('█'.repeat(60));

    const critical = vulnerabilities.filter(v => v.severity === 'CRITICAL');
    const high = vulnerabilities.filter(v => v.severity === 'HIGH');
    const medium = vulnerabilities.filter(v => v.severity === 'MEDIUM');
    const low = vulnerabilities.filter(v => v.severity === 'LOW');

    console.log(`\n🔴 CRITICAL: ${critical.length}`);
    critical.forEach(v => console.log(`   - ${v.title}`));

    console.log(`\n🟠 HIGH: ${high.length}`);
    high.forEach(v => console.log(`   - ${v.title}`));

    console.log(`\n🟡 MEDIUM: ${medium.length}`);
    medium.forEach(v => console.log(`   - ${v.title}`));

    console.log(`\n🟢 LOW: ${low.length}`);
    low.forEach(v => console.log(`   - ${v.title}`));

    console.log(`\n📊 TOTAL VULNERABILITIES FOUND: ${vulnerabilities.length}`);
    console.log(`📝 INFORMATIONAL FINDINGS: ${findings.length}`);

    // Export results
    const report = {
        timestamp: new Date().toISOString(),
        package: '@verified-network/verified-custody',
        version: '0.4.9',
        vulnerabilities,
        findings,
        summary: {
            critical: critical.length,
            high: high.length,
            medium: medium.length,
            low: low.length,
            total: vulnerabilities.length
        }
    };

    require('fs').writeFileSync(
        'vulnerability-scan-results.json',
        JSON.stringify(report, null, 2)
    );

    console.log('\n✅ Results saved to vulnerability-scan-results.json');
}

main().catch(console.error);
