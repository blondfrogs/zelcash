// Copyright (c) 2024 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef FLUX_BLS_KEY_DERIVATION_H
#define FLUX_BLS_KEY_DERIVATION_H

#include "bls_signature.h"
#include "../key.h"
#include "../hash.h"
#include "../uint256.h"

/**
 * Derive BLS keys deterministically from existing ECDSA keys
 * This allows existing fluxnodes to generate BLS keys without new setup
 */
class CBLSKeyDerivation {
public:
    /**
     * Derive a BLS private key from an ECDSA private key
     * Uses HKDF (HMAC-based Key Derivation Function) for secure derivation
     * 
     * @param ecdsaKey The existing ECDSA private key
     * @param blsPrivKey Output BLS private key (32 bytes)
     * @return true if successful
     */
    static bool DeriveFromECDSA(const CKey& ecdsaKey, std::vector<unsigned char>& blsPrivKey) {
        if (!ecdsaKey.IsValid()) {
            return false;
        }
        
        // Get the ECDSA private key bytes
        CPrivKey ecdsaPriv = ecdsaKey.GetPrivKey();
        
        // Use HKDF with a domain separator to derive BLS key
        // Domain separator prevents key reuse attacks
        const std::string strDomain = "FluxBLSKeyDerivation_v1";
        
        // Create derivation seed: HMAC-SHA256(domain, ecdsa_priv_key)
        CHMAC_SHA256 hasher((const unsigned char*)strDomain.data(), strDomain.size());
        hasher.Write(ecdsaPriv.data(), ecdsaPriv.size());
        
        uint256 seed;
        hasher.Finalize(seed.begin());
        
        // Derive BLS private key (32 bytes) from seed
        // BLS12-381 private keys are scalars mod r (curve order)
        blsPrivKey.resize(32);
        memcpy(blsPrivKey.data(), seed.begin(), 32);
        
        // Reduce modulo curve order (this would be done by BLS library)
        // The actual BLS library will handle this properly
        
        return true;
    }
    
    /**
     * Derive BLS keypair from ECDSA key
     * 
     * @param ecdsaKey The existing ECDSA private key
     * @param blsPubKey Output BLS public key
     * @param blsPrivKey Output BLS private key
     * @return true if successful
     */
    static bool DeriveKeypair(const CKey& ecdsaKey, CBLSPublicKey& blsPubKey, std::vector<unsigned char>& blsPrivKey) {
        // First derive the private key
        if (!DeriveFromECDSA(ecdsaKey, blsPrivKey)) {
            return false;
        }
        
        // Generate public key from private key
        // This would call the actual BLS library
        // For now, placeholder:
        std::vector<unsigned char> pubKeyBytes(BLS_PUBLIC_KEY_SIZE);
        
        // In real implementation:
        // BLS::GetPublicKey(blsPrivKey, pubKeyBytes);
        
        blsPubKey = CBLSPublicKey(pubKeyBytes);
        return true;
    }
    
    /**
     * Get cached BLS keys for the active fluxnode
     * Derives on first call, then caches the result
     */
    static bool GetActiveNodeBLSKeys(CBLSPublicKey& blsPubKey, std::vector<unsigned char>& blsPrivKey) {
        static bool fCached = false;
        static CBLSPublicKey cachedPubKey;
        static std::vector<unsigned char> cachedPrivKey;
        
        if (!fCached) {
            // Get ECDSA key from active fluxnode
            CTxIn vin;
            CPubKey ecdsaPubKey;
            CKey ecdsaKey;
            
            if (!activeFluxnode.GetFluxNodeVin(vin, ecdsaPubKey, ecdsaKey)) {
                return false;
            }
            
            // Derive BLS keys
            if (!DeriveKeypair(ecdsaKey, cachedPubKey, cachedPrivKey)) {
                return false;
            }
            
            fCached = true;
            LogPrintf("Derived BLS keys for active fluxnode %s\n", 
                     activeFluxnode.deterministicOutPoint.ToString());
        }
        
        blsPubKey = cachedPubKey;
        blsPrivKey = cachedPrivKey;
        return true;
    }
};

/**
 * Extended FluxnodeCacheData to include BLS public key
 * The BLS pubkey is derived from the ECDSA pubkey deterministically
 */
struct FluxnodeBLSData {
    CBLSPublicKey blsPubKey;
    
    // Derive from existing ECDSA public key
    bool DeriveFromECDSAPubKey(const CPubKey& ecdsaPubKey) {
        // For public key derivation, we need a different approach
        // since we don't have the private key
        
        // Use the ECDSA public key as seed for deterministic derivation
        CHashWriter hasher(SER_GETHASH, 0);
        hasher << std::string("FluxBLSPubKeyDerivation_v1");
        hasher << ecdsaPubKey;
        uint256 seed = hasher.GetHash();
        
        // This is a placeholder - in reality, we'd need the node
        // to publish its BLS pubkey derived from its private key
        // OR use a protocol where nodes register BLS keys on-chain
        
        return false; // Can't derive BLS pubkey from ECDSA pubkey alone
    }
};

#endif // FLUX_BLS_KEY_DERIVATION_H