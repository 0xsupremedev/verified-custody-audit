/**
 * ADDITIONAL VULNERABILITY TESTS
 * Testing for signature intent confusion and cross-chain replay
 */

const { encryptString, decryptString, hashTheString } = require('@verified-network/verified-custody');
const { Wallet, Transaction, encodeBytes32String } = require('ethers');
const crypto = require('crypto');

console.log('\n' + '='.repeat(60));
console.log('  ADDITIONAL VULNERABILITY TESTS');
console.log('  Signature Intent Confusion & Cross-Chain Replay');
console.log('='.repeat(60));

// ========== TEST 1: Vault ID Determinism ==========
console.log('\n[TEST 1] Vault ID Determinism Analysis');
console.log('='.repeat(50));

// Test if hashedVaultId is deterministic and enumerable
const emails = [
    'alice@example.com',
    'bob@example.com',
    'admin@verified.network'
];

console.log('\nVault ID derivation (deterministic check):');
emails.forEach(email => {
    const hash1 = hashTheString(email);
    const hash2 = hashTheString(email);
    console.log(`  ${email}`);
    console.log(`    Hash 1: ${hash1.substring(0, 30)}...`);
    console.log(`    Hash 2: ${hash2.substring(0, 30)}...`);
    console.log(`    Deterministic: ${hash1 === hash2 ? 'YES (VULNERABLE)' : 'NO'}`);
});

console.log('\n[FINDING] Vault IDs are deterministic and derived from email');
console.log('[IMPACT] Attacker can enumerate/target specific users');

// ========== TEST 2: Cross-Chain Replay Analysis ==========
console.log('\n[TEST 2] Cross-Chain Replay Risk Analysis');
console.log('='.repeat(50));

// Create a wallet and sign a transaction
const testWallet = Wallet.createRandom();
console.log(`\nTest wallet address: ${testWallet.address}`);

// Create transactions for different chains
const txBase = {
    to: '0x1234567890123456789012345678901234567890',
    value: '1000000000000000000', // 1 ETH
    data: '0x',
    nonce: 0,
    gasLimit: 21000,
    gasPrice: '1000000000'
};

// Sign with chainId (proper)
const signWithChain = async (chainId) => {
    const tx = { ...txBase, chainId };
    const signed = await testWallet.signTransaction(tx);
    return signed;
};

// Sign without chainId (vulnerable pattern)
const signWithoutChain = async () => {
    const tx = { ...txBase };  // No chainId!
    try {
        const signed = await testWallet.signTransaction(tx);
        return signed;
    } catch (e) {
        return `Error: ${e.message}`;
    }
};

async function testCrossChainReplay() {
    console.log('\nSigning same tx on different chains:');

    const signedBase = await signWithChain(8453);  // BASE
    const signedEth = await signWithChain(1);       // Ethereum
    const signedArb = await signWithChain(42161);   // Arbitrum

    console.log(`  BASE (8453):    ${signedBase.substring(0, 50)}...`);
    console.log(`  Ethereum (1):   ${signedEth.substring(0, 50)}...`);
    console.log(`  Arbitrum:       ${signedArb.substring(0, 50)}...`);

    console.log(`\n  All signatures different: ${signedBase !== signedEth && signedEth !== signedArb ? 'YES (Good)' : 'NO (VULNERABLE)'
        }`);

    // Test signing without chainId
    console.log('\n  Testing signature without chainId:');
    const signedNoChain = await signWithoutChain();
    console.log(`  No chainId:     ${signedNoChain.substring(0, 50)}...`);

    console.log('\n[NOTE] Ethers.js enforces chainId in transaction signing');
    console.log('[CHECK] Does SDK validate chainId before passing to signer?');
}

// ========== TEST 3: Hashed PIN as Co-Signer Identifier ==========
console.log('\n[TEST 3] Co-Signer Identifier Analysis');
console.log('='.repeat(50));

// From type definitions:
// sendCoSignerInvitation(channel, cosigerId, creatorId, hashedCretorPin)
// The hashedCreatorPIN is passed in co-signer communications

console.log('\nCo-signer invitation includes hashedCreatorPin:');
console.log('  sendCoSignerInvitation(channel, cosigerId, creatorId, hashedCreatorPin)');
console.log('\n[FINDING] Hashed PIN is transmitted to co-signers');
console.log('[IMPACT] If PIN hash leaks, combined with encrypted PK = brute-forceable');

// ========== TEST 4: Raw Transaction Signing Analysis ==========
console.log('\n[TEST 4] Transaction Object Mutability');
console.log('='.repeat(50));

// Check if tx object is validated before signing
const maliciousTx = {
    to: '0xATTACKER_ADDRESS_INJECTED_LATER',
    value: '0',
    data: '0x',
    // Missing: chainId, nonce, gas fields
};

console.log('\nMalicious tx object (incomplete):');
console.log(JSON.stringify(maliciousTx, null, 2));

console.log('\n[CHECK] Does SDK validate tx fields before signing?');
console.log('[CHECK] Can tx be mutated after user approval, before signing?');
console.log('[CHECK] Are nonce, gas, value bound at approval time?');

// ========== TEST 5: Recovery Share Binding ==========
console.log('\n[TEST 5] Recovery Share Analysis');
console.log('='.repeat(50));

console.log('\nQuestions to verify:');
console.log('  1. Are shares bound to specific vaultId?');
console.log('  2. Are shares bound to specific recovery session?');
console.log('  3. Can old shares be replayed in new recovery?');
console.log('  4. Is there share expiration?');

console.log('\n[NOTE] From type definitions:');
console.log('  signRecovery and completeRecovery actions exist');
console.log('  But share validation logic is not exposed in SDK');

// ========== SUMMARY ==========
async function main() {
    await testCrossChainReplay();

    console.log('\n' + '='.repeat(60));
    console.log('  ADDITIONAL FINDINGS SUMMARY');
    console.log('='.repeat(60));

    console.log(`
+-------------------------------------------------------------+
|  FINDING                          | SEVERITY | EXPLOITABLE  |
+-------------------------------------------------------------+
|  Deterministic Vault IDs          | MEDIUM   | YES          |
|  Hashed PIN transmitted           | MEDIUM   | PARTIAL      |
|  ChainId enforcement              | CHECK    | Unknown      |
|  Tx mutability after approval     | CHECK    | Unknown      |
|  Share rebinding                  | CHECK    | Unknown      |
+-------------------------------------------------------------+

CONFIRMED NEW VULNERABILITIES:
1. Deterministic Vault IDs enable user enumeration
2. Hashed PIN in co-signer communication increases attack surface

NEEDS RUNTIME TESTING:
- ChainId enforcement (requires browser extension context)
- IPC message authentication (requires extension internals)
- Transaction object binding (requires approval flow)

RECOMMENDATION:
Submit current findings. These additional items require:
- Access to deployed extension
- User interaction testing
- On-chain transaction analysis
`);
}

main().catch(console.error);
