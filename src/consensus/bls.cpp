// Copyright (c) 2024 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "bls.h"
#include "../util.h"
#include "../random.h"

#ifdef HAVE_BLST
#include <blst/blst.hpp>
#endif

namespace BLS {

#ifdef HAVE_BLST

// Domain separation tag for Flux BLS signatures
static const std::string DST = "FLUX_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

bool GenerateKeypair(CBLSSecretKey& secretKey, CBLSPublicKey& publicKey) {
    try {
        // Generate random 32-byte secret key
        std::vector<unsigned char> ikm(32);
        GetRandBytes(ikm.data(), 32);
        
        // Derive BLS secret key using key generation
        blst::SecretKey sk;
        sk.keygen(ikm.data(), ikm.size());
        
        // Store secret key (32 bytes)
        secretKey = CBLSSecretKey();
        secretKey.vchKey.resize(32);
        sk.to_bendian(secretKey.vchKey.data());
        
        // Generate public key from secret key
        blst::P1 pk = blst::P1(sk);
        
        // Serialize public key (48 bytes compressed)
        publicKey = CBLSPublicKey();
        publicKey.vchPubKey.resize(48);
        pk.compress(publicKey.vchPubKey.data());
        
        return true;
    } catch (const std::exception& e) {
        LogPrintf("BLS::GenerateKeypair: Exception caught: %s\n", e.what());
        return false;
    } catch (...) {
        LogPrintf("BLS::GenerateKeypair: Unknown exception caught\n");
        return false;
    }
}

bool DeriveFromSeed(const std::vector<unsigned char>& seed, CBLSSecretKey& secretKey, CBLSPublicKey& publicKey) {
    if (seed.size() < 32) {
        return false;
    }
    
    try {
        // Derive BLS secret key from seed
        blst::SecretKey sk;
        sk.keygen(seed.data(), seed.size(), std::string("FLUX_BLS_DERIVATION"));
        
        // Store secret key (32 bytes)
        secretKey = CBLSSecretKey();
        secretKey.vchKey.resize(32);
        sk.to_bendian(secretKey.vchKey.data());
        
        // Generate public key from secret key
        blst::P1 pk = blst::P1(sk);
        
        // Serialize public key (48 bytes compressed)
        publicKey = CBLSPublicKey();
        publicKey.vchPubKey.resize(48);
        pk.compress(publicKey.vchPubKey.data());
        
        return true;
    } catch (const std::exception& e) {
        LogPrintf("BLS::DeriveFromSeed: Exception caught: %s\n", e.what());
        return false;
    } catch (...) {
        LogPrintf("BLS::DeriveFromSeed: Unknown exception caught\n");
        return false;
    }
}

bool Sign(const uint256& message, const CBLSSecretKey& secretKey, CBLSSignature& signature) {
    if (!secretKey.IsValid()) {
        return false;
    }
    
    // Create secret key object from bytes
    blst::SecretKey sk;
    sk.from_bendian(secretKey.vchKey.data());
    
    // Hash message to G2 and sign
    blst::P2 sig;
    sig.hash_to(message.begin(), 32, DST);
    sig.sign_with(sk);
    
    // Convert to affine and compress
    blst::P2_Affine sig_affine(sig);
    signature = CBLSSignature();
    signature.vchSig.resize(96);
    sig_affine.compress(signature.vchSig.data());
    
    return true;
}

bool Verify(const uint256& message, const CBLSPublicKey& publicKey, const CBLSSignature& signature) {
    if (!publicKey.IsValid() || !signature.IsValid()) {
        return false;
    }
    
    try {
        // Deserialize public key
        blst::P1_Affine pk_affine(publicKey.vchPubKey.data());
        
        // Deserialize signature
        blst::P2_Affine sig_affine(signature.vchSig.data());
        
        // Verify signature using core_verify
        // Parameters: pk, hash_or_encode=true (we hash), message, DST
        blst::BLST_ERROR result = sig_affine.core_verify(
            pk_affine,
            true,  // hash_or_encode = true (hash the message)
            message.begin(),
            32,
            DST
        );
        
        return result == blst::BLST_SUCCESS;
    } catch (...) {
        return false;
    }
}

bool Aggregate(const std::vector<CBLSSignature>& signatures, CBLSAggregateSignature& aggregateSig) {
    if (signatures.empty()) {
        return false;
    }
    
    try {
        // Start with first signature
        blst::P2_Affine first_sig(signatures[0].vchSig.data());
        blst::P2 agg_sig = blst::P2(first_sig);
        
        // Add remaining signatures using the add method
        for (size_t i = 1; i < signatures.size(); i++) {
            blst::P2_Affine sig_affine(signatures[i].vchSig.data());
            agg_sig.add(sig_affine);
        }
        
        // Convert to affine and serialize
        blst::P2_Affine agg_affine(agg_sig);
        aggregateSig = CBLSAggregateSignature();
        aggregateSig.vchAggSig.resize(96);
        agg_affine.compress(aggregateSig.vchAggSig.data());
        
        return true;
    } catch (...) {
        return false;
    }
}

bool VerifyAggregate(const uint256& message, 
                    const std::vector<CBLSPublicKey>& publicKeys,
                    const CBLSAggregateSignature& aggregateSig) {
    if (publicKeys.empty() || !aggregateSig.IsValid()) {
        return false;
    }
    
    try {
        // Deserialize aggregate signature
        blst::P2_Affine agg_sig_affine(aggregateSig.vchAggSig.data());
        
        // Aggregate public keys based on bitmap
        blst::P1 agg_pk;
        bool first = true;
        
        for (size_t i = 0; i < publicKeys.size() && i < 32; i++) {
            if (aggregateSig.HasSigner(i)) {
                blst::P1_Affine pk_affine(publicKeys[i].vchPubKey.data());
                
                if (first) {
                    agg_pk = blst::P1(pk_affine);
                    first = false;
                } else {
                    agg_pk.add(pk_affine);
                }
            }
        }
        
        if (first) { // No signers
            return false;
        }
        
        // Convert aggregated pubkey to affine
        blst::P1_Affine agg_pk_affine(agg_pk);
        
        // Verify aggregate signature
        blst::BLST_ERROR result = agg_sig_affine.core_verify(
            agg_pk_affine,
            true,  // hash_or_encode = true
            message.begin(),
            32,
            DST
        );
        
        return result == blst::BLST_SUCCESS;
    } catch (...) {
        return false;
    }
}

#else // !HAVE_BLST

// Stub implementations when BLST is not available
bool GenerateKeypair(CBLSSecretKey& secretKey, CBLSPublicKey& publicKey) {
    LogPrintf("BLS: BLST library not available\n");
    return false;
}

bool DeriveFromSeed(const std::vector<unsigned char>& seed, CBLSSecretKey& secretKey, CBLSPublicKey& publicKey) {
    LogPrintf("BLS: BLST library not available\n");
    return false;
}

bool Sign(const uint256& message, const CBLSSecretKey& secretKey, CBLSSignature& signature) {
    LogPrintf("BLS: BLST library not available\n");
    return false;
}

bool Verify(const uint256& message, const CBLSPublicKey& publicKey, const CBLSSignature& signature) {
    LogPrintf("BLS: BLST library not available\n");
    return false;
}

bool Aggregate(const std::vector<CBLSSignature>& signatures, CBLSAggregateSignature& aggregateSig) {
    LogPrintf("BLS: BLST library not available\n");
    return false;
}

bool VerifyAggregate(const uint256& message, 
                    const std::vector<CBLSPublicKey>& publicKeys,
                    const CBLSAggregateSignature& aggregateSig) {
    LogPrintf("BLS: BLST library not available\n");
    return false;
}

#endif // HAVE_BLST

} // namespace BLS