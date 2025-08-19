// Copyright (c) 2024 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef FLUX_BLS_KEY_MANAGER_H
#define FLUX_BLS_KEY_MANAGER_H

#include "bls.h"
#include "../key.h"
#include "../pubkey.h"
#include "../uint256.h"
#include "../sync.h"
#include <map>
#include <memory>

/**
 * BLS Key Manager
 * 
 * Manages BLS key derivation from ECDSA keys for fluxnode consensus.
 * Keys are derived deterministically so nodes don't need new key management.
 */
class CBLSKeyManager {
private:
    mutable CCriticalSection cs_blsKeys;
    
    // Cache of derived BLS keys (ECDSA pubkey hash -> BLS keypair)
    mutable std::map<uint256, std::pair<CBLSSecretKey, CBLSPublicKey>> mapBLSKeys;
    
    // Active BLS key for this node
    CBLSSecretKey activeSecretKey;
    CBLSPublicKey activePublicKey;
    bool fHasActiveKey;
    
    // Derive BLS key from ECDSA private key
    bool DeriveKey(const CKey& ecdsaKey, CBLSSecretKey& blsSecret, CBLSPublicKey& blsPublic) const;
    
public:
    CBLSKeyManager() : fHasActiveKey(false) {}
    
    // Initialize with the node's ECDSA private key
    bool InitializeFromECDSA(const std::string& strPrivKey);
    bool InitializeFromECDSA(const CKey& ecdsaKey);
    
    // Get BLS public key for an ECDSA public key (for verification)
    bool GetBLSPublicKey(const CPubKey& ecdsaPubKey, CBLSPublicKey& blsPubKey) const;
    
    // Get active BLS keys for signing
    bool GetActiveKeys(CBLSSecretKey& secret, CBLSPublicKey& pubkey) const;
    bool HasActiveKey() const { return fHasActiveKey; }
    
    // Sign a message with active BLS key
    bool SignMessage(const uint256& msgHash, CBLSSignature& signature) const;
    
    // Verify a BLS signature given ECDSA public key
    bool VerifySignature(const uint256& msgHash, const CBLSSignature& signature, 
                        const CPubKey& ecdsaPubKey) const;
    
    // Clear all cached keys
    void Clear();
    
    // For testing: derive and cache a set of keys
    bool CacheKeysForTesting(const std::vector<CKey>& ecdsaKeys);
};

// Global BLS key manager instance
extern CBLSKeyManager blsKeyManager;

#endif // FLUX_BLS_KEY_MANAGER_H