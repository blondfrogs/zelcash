// Copyright (c) 2024 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "test/test_bitcoin.h"
#include "../consensus/bls.h"
#include "../consensus/bls_key_manager.h"
#include "../key.h"
#include "../pubkey.h"
#include "../random.h"
#include "../uint256.h"
#include "../util.h"

#include <boost/test/unit_test.hpp>
#include <chrono>

BOOST_FIXTURE_TEST_SUITE(bls_tests, BasicTestingSetup)

// Test basic BLS functionality
BOOST_AUTO_TEST_CASE(bls_basic_operations)
{
    // Generate a keypair
    CBLSSecretKey secretKey;
    CBLSPublicKey publicKey;
    
    BOOST_CHECK(BLS::GenerateKeypair(secretKey, publicKey));
    BOOST_CHECK(secretKey.IsValid());
    BOOST_CHECK(publicKey.IsValid());
    
    // Sign a message
    uint256 msgHash = GetRandHash();
    CBLSSignature signature;
    
    BOOST_CHECK(BLS::Sign(msgHash, secretKey, signature));
    BOOST_CHECK(signature.IsValid());
    
    // Verify the signature
    BOOST_CHECK(BLS::Verify(msgHash, publicKey, signature));
    
    // Wrong message should fail
    uint256 wrongMsg = GetRandHash();
    BOOST_CHECK(!BLS::Verify(wrongMsg, publicKey, signature));
}

// Test deterministic key derivation from ECDSA
BOOST_AUTO_TEST_CASE(bls_key_derivation_deterministic)
{
    // Generate ECDSA key
    CKey ecdsaKey;
    ecdsaKey.MakeNewKey(true);
    
    // Derive BLS key multiple times - should be deterministic
    CBLSKeyManager manager1;
    CBLSKeyManager manager2;
    
    BOOST_CHECK(manager1.InitializeFromECDSA(ecdsaKey));
    BOOST_CHECK(manager2.InitializeFromECDSA(ecdsaKey));
    
    CBLSSecretKey secret1, secret2;
    CBLSPublicKey public1, public2;
    
    BOOST_CHECK(manager1.GetActiveKeys(secret1, public1));
    BOOST_CHECK(manager2.GetActiveKeys(secret2, public2));
    
    // Keys should be identical
    BOOST_CHECK(secret1.vchKey == secret2.vchKey);
    BOOST_CHECK(public1 == public2);
}

// Test signature aggregation for quorum
BOOST_AUTO_TEST_CASE(bls_signature_aggregation)
{
    const int QUORUM_SIZE = 21;
    std::vector<CBLSSecretKey> secretKeys;
    std::vector<CBLSPublicKey> publicKeys;
    std::vector<CBLSSignature> signatures;
    
    // Generate keys for quorum members
    for (int i = 0; i < QUORUM_SIZE; i++) {
        CBLSSecretKey secret;
        CBLSPublicKey pubkey;
        
        BOOST_CHECK(BLS::GenerateKeypair(secret, pubkey));
        secretKeys.push_back(secret);
        publicKeys.push_back(pubkey);
    }
    
    // All sign the same message
    uint256 msgHash = GetRandHash();
    
    for (int i = 0; i < QUORUM_SIZE; i++) {
        CBLSSignature sig;
        BOOST_CHECK(BLS::Sign(msgHash, secretKeys[i], sig));
        signatures.push_back(sig);
    }
    
    // Aggregate signatures
    CBLSAggregateSignature aggSig;
    BOOST_CHECK(BLS::Aggregate(signatures, aggSig));
    BOOST_CHECK(aggSig.IsValid());
    
    // Set bitmap for all signers
    aggSig.nSignerBitmap = (1 << QUORUM_SIZE) - 1;
    
    // Verify aggregate signature
    BOOST_CHECK(BLS::VerifyAggregate(msgHash, publicKeys, aggSig));
    
    // Test partial aggregation (14 out of 21)
    std::vector<CBLSSignature> partialSigs(signatures.begin(), signatures.begin() + 14);
    CBLSAggregateSignature partialAgg;
    BOOST_CHECK(BLS::Aggregate(partialSigs, partialAgg));
    
    // Set bitmap for partial signers
    partialAgg.nSignerBitmap = (1 << 14) - 1;
    
    // Should still verify with correct subset
    BOOST_CHECK(BLS::VerifyAggregate(msgHash, publicKeys, partialAgg));
}

// Test BLS key manager integration
BOOST_AUTO_TEST_CASE(bls_key_manager_operations)
{
    CBLSKeyManager manager;
    
    // Initialize with ECDSA key
    CKey ecdsaKey;
    ecdsaKey.MakeNewKey(true);
    
    BOOST_CHECK(manager.InitializeFromECDSA(ecdsaKey));
    BOOST_CHECK(manager.HasActiveKey());
    
    // Sign a message
    uint256 msgHash = GetRandHash();
    CBLSSignature signature;
    
    BOOST_CHECK(manager.SignMessage(msgHash, signature));
    BOOST_CHECK(signature.IsValid());
    
    // Get public key and verify
    CBLSSecretKey secret;
    CBLSPublicKey pubkey;
    BOOST_CHECK(manager.GetActiveKeys(secret, pubkey));
    
    // Verify signature
    BOOST_CHECK(BLS::Verify(msgHash, pubkey, signature));
}

// Performance benchmark for BLS vs ECDSA
BOOST_AUTO_TEST_CASE(bls_performance_comparison)
{
    const int NUM_SIGNATURES = 100;
    
    // Setup ECDSA
    std::vector<CKey> ecdsaKeys;
    std::vector<CPubKey> ecdsaPubKeys;
    for (int i = 0; i < NUM_SIGNATURES; i++) {
        CKey key;
        key.MakeNewKey(true);
        ecdsaKeys.push_back(key);
        ecdsaPubKeys.push_back(key.GetPubKey());
    }
    
    // Setup BLS
    std::vector<CBLSSecretKey> blsSecrets;
    std::vector<CBLSPublicKey> blsPubKeys;
    for (int i = 0; i < NUM_SIGNATURES; i++) {
        CBLSSecretKey secret;
        CBLSPublicKey pubkey;
        BLS::GenerateKeypair(secret, pubkey);
        blsSecrets.push_back(secret);
        blsPubKeys.push_back(pubkey);
    }
    
    uint256 msgHash = GetRandHash();
    
    // Benchmark ECDSA signing
    auto start = std::chrono::high_resolution_clock::now();
    std::vector<std::vector<unsigned char>> ecdsaSigs;
    for (int i = 0; i < NUM_SIGNATURES; i++) {
        std::vector<unsigned char> sig;
        BOOST_CHECK(ecdsaKeys[i].Sign(msgHash, sig));
        ecdsaSigs.push_back(sig);
    }
    auto ecdsaSignTime = std::chrono::high_resolution_clock::now() - start;
    
    // Benchmark BLS signing
    start = std::chrono::high_resolution_clock::now();
    std::vector<CBLSSignature> blsSigs;
    for (int i = 0; i < NUM_SIGNATURES; i++) {
        CBLSSignature sig;
        BOOST_CHECK(BLS::Sign(msgHash, blsSecrets[i], sig));
        blsSigs.push_back(sig);
    }
    auto blsSignTime = std::chrono::high_resolution_clock::now() - start;
    
    // Benchmark ECDSA verification
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < NUM_SIGNATURES; i++) {
        BOOST_CHECK(ecdsaPubKeys[i].Verify(msgHash, ecdsaSigs[i]));
    }
    auto ecdsaVerifyTime = std::chrono::high_resolution_clock::now() - start;
    
    // Benchmark BLS verification
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < NUM_SIGNATURES; i++) {
        BOOST_CHECK(BLS::Verify(msgHash, blsPubKeys[i], blsSigs[i]));
    }
    auto blsVerifyTime = std::chrono::high_resolution_clock::now() - start;
    
    // Benchmark BLS aggregation
    start = std::chrono::high_resolution_clock::now();
    CBLSAggregateSignature aggSig;
    BOOST_CHECK(BLS::Aggregate(blsSigs, aggSig));
    auto blsAggTime = std::chrono::high_resolution_clock::now() - start;
    
    // Print results
    LogPrintf("\n=== BLS vs ECDSA Performance (%d signatures) ===\n", NUM_SIGNATURES);
    LogPrintf("ECDSA Sign: %lld us\n", 
             std::chrono::duration_cast<std::chrono::microseconds>(ecdsaSignTime).count());
    LogPrintf("BLS Sign: %lld us\n", 
             std::chrono::duration_cast<std::chrono::microseconds>(blsSignTime).count());
    LogPrintf("ECDSA Verify: %lld us\n", 
             std::chrono::duration_cast<std::chrono::microseconds>(ecdsaVerifyTime).count());
    LogPrintf("BLS Verify: %lld us\n", 
             std::chrono::duration_cast<std::chrono::microseconds>(blsVerifyTime).count());
    LogPrintf("BLS Aggregate: %lld us\n", 
             std::chrono::duration_cast<std::chrono::microseconds>(blsAggTime).count());
    
    // Size comparison
    LogPrintf("\n=== Size Comparison ===\n");
    LogPrintf("ECDSA signature: %d bytes\n", ecdsaSigs[0].size());
    LogPrintf("BLS signature: %d bytes\n", BLS_SIGNATURE_SIZE);
    LogPrintf("BLS aggregate signature: %d bytes\n", aggSig.vchAggSig.size());
    LogPrintf("%d ECDSA signatures: %d bytes\n", 
             NUM_SIGNATURES, NUM_SIGNATURES * ecdsaSigs[0].size());
    LogPrintf("1 BLS aggregate: %d bytes (%.1f%% reduction)\n", 
             aggSig.vchAggSig.size() + 4, // +4 for bitmap
             100.0 * (1.0 - (double)(aggSig.vchAggSig.size() + 4) / 
                     (NUM_SIGNATURES * ecdsaSigs[0].size())));
}

// Test fluxnode consensus signature scenario
BOOST_AUTO_TEST_CASE(bls_fluxnode_consensus_simulation)
{
    const int QUORUM_SIZE = 21;
    const int THRESHOLD = 14;
    
    // Simulate fluxnode keys
    std::vector<CKey> ecdsaKeys;
    std::vector<CBLSKeyManager*> managers;
    
    for (int i = 0; i < QUORUM_SIZE; i++) {
        CKey key;
        key.MakeNewKey(true);
        ecdsaKeys.push_back(key);
        
        CBLSKeyManager* manager = new CBLSKeyManager();
        BOOST_CHECK(manager->InitializeFromECDSA(key));
        managers.push_back(manager);
    }
    
    // Simulate block signing
    uint256 blockHash = GetRandHash();
    std::vector<CBLSSignature> signatures;
    std::vector<CBLSPublicKey> publicKeys;
    
    // First THRESHOLD nodes sign
    for (int i = 0; i < THRESHOLD; i++) {
        CBLSSignature sig;
        BOOST_CHECK(managers[i]->SignMessage(blockHash, sig));
        signatures.push_back(sig);
        
        CBLSSecretKey secret;
        CBLSPublicKey pubkey;
        BOOST_CHECK(managers[i]->GetActiveKeys(secret, pubkey));
        publicKeys.push_back(pubkey);
    }
    
    // Aggregate the signatures
    CBLSAggregateSignature aggSig;
    BOOST_CHECK(BLS::Aggregate(signatures, aggSig));
    
    // Set bitmap for signers
    aggSig.nSignerBitmap = (1 << THRESHOLD) - 1;
    
    // Verify aggregate
    BOOST_CHECK(BLS::VerifyAggregate(blockHash, publicKeys, aggSig));
    
    LogPrintf("\n=== Fluxnode Consensus Simulation ===\n");
    LogPrintf("Quorum size: %d\n", QUORUM_SIZE);
    LogPrintf("Signatures collected: %d\n", THRESHOLD);
    LogPrintf("Individual signature size: %d bytes\n", BLS_SIGNATURE_SIZE);
    LogPrintf("Total with ECDSA: %d bytes\n", THRESHOLD * 120); // Approximate ECDSA sig size
    LogPrintf("BLS aggregate: %d bytes\n", aggSig.vchAggSig.size() + 4);
    LogPrintf("Space saved: %.1f%%\n", 
             100.0 * (1.0 - (double)(aggSig.vchAggSig.size() + 4) / (THRESHOLD * 120)));
    
    // Cleanup
    for (auto* manager : managers) {
        delete manager;
    }
}

BOOST_AUTO_TEST_SUITE_END()