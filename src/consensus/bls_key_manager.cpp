// Copyright (c) 2024 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "bls_key_manager.h"
#include "bls.h"
#include "../hash.h"
#include "../util.h"
#include "../key_io.h"
#include "../utilstrencodings.h"

// Global instance
CBLSKeyManager blsKeyManager;

bool CBLSKeyManager::DeriveKey(const CKey& ecdsaKey, CBLSSecretKey& blsSecret, CBLSPublicKey& blsPublic) const {
    if (!ecdsaKey.IsValid()) {
        LogPrintf("BLSKeyManager: Invalid ECDSA key provided\n");
        return false;
    }
    
    // Create seed from ECDSA private key using HMAC-SHA256
    // This ensures a deterministic but cryptographically secure derivation
    std::vector<unsigned char> vchPrivKey(ecdsaKey.begin(), ecdsaKey.end());
    
    // Add domain separation to prevent key reuse attacks
    std::string strDomain = "FLUX_BLS_KEY_DERIVATION_V1";
    std::vector<unsigned char> vchDomain(strDomain.begin(), strDomain.end());
    
    // Combine domain and private key
    std::vector<unsigned char> vchSeed;
    vchSeed.insert(vchSeed.end(), vchDomain.begin(), vchDomain.end());
    vchSeed.insert(vchSeed.end(), vchPrivKey.begin(), vchPrivKey.end());
    
    // Hash to create seed (using SHA256 twice for extra security)
    uint256 hash1 = Hash(vchSeed.begin(), vchSeed.end());
    uint256 hash2 = Hash(hash1.begin(), hash1.end());
    
    // Use the double hash as seed for BLS key generation
    std::vector<unsigned char> vchBLSSeed(hash2.begin(), hash2.end());
    
    // Derive BLS key from seed
    if (!BLS::DeriveFromSeed(vchBLSSeed, blsSecret, blsPublic)) {
        LogPrintf("BLSKeyManager: Failed to derive BLS key from seed\n");
        return false;
    }
    
    LogPrint("bls", "BLSKeyManager: Successfully derived BLS key from ECDSA key\n");
    return true;
}

bool CBLSKeyManager::InitializeFromECDSA(const std::string& strPrivKey) {
    // Decode the private key using DecodeSecret
    CKey key = DecodeSecret(strPrivKey);
    if (!key.IsValid()) {
        LogPrintf("BLSKeyManager: Invalid private key\n");
        return false;
    }
    
    return InitializeFromECDSA(key);
}

bool CBLSKeyManager::InitializeFromECDSA(const CKey& ecdsaKey) {
    LOCK(cs_blsKeys);
    
    if (!ecdsaKey.IsValid()) {
        LogPrintf("BLSKeyManager: Invalid ECDSA key\n");
        return false;
    }
    
    // Derive BLS key
    CBLSSecretKey blsSecret;
    CBLSPublicKey blsPublic;
    
    if (!DeriveKey(ecdsaKey, blsSecret, blsPublic)) {
        LogPrintf("BLSKeyManager: Failed to derive BLS key\n");
        return false;
    }
    
    // Store as active key
    activeSecretKey = blsSecret;
    activePublicKey = blsPublic;
    fHasActiveKey = true;
    
    // Also cache it
    CPubKey ecdsaPubKey = ecdsaKey.GetPubKey();
    uint256 pubKeyHash = Hash(ecdsaPubKey.begin(), ecdsaPubKey.end());
    mapBLSKeys[pubKeyHash] = std::make_pair(blsSecret, blsPublic);
    
    LogPrintf("BLSKeyManager: Initialized BLS key from ECDSA key\n");
    LogPrint("bls", "BLS Public Key: %s\n", HexStr(blsPublic.vchPubKey));
    
    return true;
}

bool CBLSKeyManager::GetBLSPublicKey(const CPubKey& ecdsaPubKey, CBLSPublicKey& blsPubKey) const {
    LOCK(cs_blsKeys);
    
    // Check cache first
    uint256 pubKeyHash = Hash(ecdsaPubKey.begin(), ecdsaPubKey.end());
    auto it = mapBLSKeys.find(pubKeyHash);
    if (it != mapBLSKeys.end()) {
        blsPubKey = it->second.second;
        return true;
    }
    
    // Not in cache - we need to derive it
    // This requires the private key, which we don't have for other nodes
    // In practice, nodes would publish their BLS public keys in confirm transactions
    
    LogPrint("bls", "BLSKeyManager: BLS public key not in cache for ECDSA key\n");
    return false;
}

bool CBLSKeyManager::GetActiveKeys(CBLSSecretKey& secret, CBLSPublicKey& pubkey) const {
    LOCK(cs_blsKeys);
    
    if (!fHasActiveKey) {
        return false;
    }
    
    secret = activeSecretKey;
    pubkey = activePublicKey;
    return true;
}

bool CBLSKeyManager::SignMessage(const uint256& msgHash, CBLSSignature& signature) const {
    LOCK(cs_blsKeys);
    
    if (!fHasActiveKey) {
        LogPrintf("BLSKeyManager: No active BLS key for signing\n");
        return false;
    }
    
    if (!BLS::Sign(msgHash, activeSecretKey, signature)) {
        LogPrintf("BLSKeyManager: Failed to sign message\n");
        return false;
    }
    
    LogPrint("bls", "BLSKeyManager: Successfully signed message %s\n", msgHash.ToString());
    return true;
}

bool CBLSKeyManager::VerifySignature(const uint256& msgHash, const CBLSSignature& signature, 
                                     const CPubKey& ecdsaPubKey) const {
    CBLSPublicKey blsPubKey;
    
    // Get the BLS public key for this ECDSA key
    if (!GetBLSPublicKey(ecdsaPubKey, blsPubKey)) {
        LogPrint("bls", "BLSKeyManager: Cannot verify - BLS public key not available\n");
        return false;
    }
    
    // Verify the signature
    if (!BLS::Verify(msgHash, blsPubKey, signature)) {
        LogPrint("bls", "BLSKeyManager: Signature verification failed\n");
        return false;
    }
    
    LogPrint("bls", "BLSKeyManager: Signature verified successfully\n");
    return true;
}

void CBLSKeyManager::Clear() {
    LOCK(cs_blsKeys);
    
    mapBLSKeys.clear();
    activeSecretKey.SetNull();
    activePublicKey.SetNull();
    fHasActiveKey = false;
    
    LogPrint("bls", "BLSKeyManager: Cleared all keys\n");
}

bool CBLSKeyManager::CacheKeysForTesting(const std::vector<CKey>& ecdsaKeys) {
    LOCK(cs_blsKeys);
    
    for (const CKey& key : ecdsaKeys) {
        if (!key.IsValid()) {
            continue;
        }
        
        CBLSSecretKey blsSecret;
        CBLSPublicKey blsPublic;
        
        if (DeriveKey(key, blsSecret, blsPublic)) {
            CPubKey ecdsaPubKey = key.GetPubKey();
            uint256 pubKeyHash = Hash(ecdsaPubKey.begin(), ecdsaPubKey.end());
            mapBLSKeys[pubKeyHash] = std::make_pair(blsSecret, blsPublic);
            
            LogPrint("bls", "Cached BLS key for ECDSA pubkey %s\n", 
                    HexStr(ecdsaPubKey));
        }
    }
    
    LogPrintf("BLSKeyManager: Cached %d BLS keys for testing\n", mapBLSKeys.size());
    return true;
}