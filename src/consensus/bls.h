// Copyright (c) 2024 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef FLUX_CONSENSUS_BLS_H
#define FLUX_CONSENSUS_BLS_H

#include "../serialize.h"
#include "../uint256.h"
#include <vector>

// BLS signature sizes
static const size_t BLS_SECRET_KEY_SIZE = 32;
static const size_t BLS_PUBLIC_KEY_SIZE = 48;
static const size_t BLS_SIGNATURE_SIZE = 96;

// BLS secret key wrapper
class CBLSSecretKey {
public:
    std::vector<unsigned char> vchKey;

    CBLSSecretKey() {}
    explicit CBLSSecretKey(const std::vector<unsigned char>& vchKeyIn) : vchKey(vchKeyIn) {}

    bool IsValid() const { return vchKey.size() == BLS_SECRET_KEY_SIZE; }
    void SetNull() { vchKey.clear(); }
    
    // Don't serialize secret keys
    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        // Secret keys should never be serialized
    }
};

// BLS public key wrapper
class CBLSPublicKey {
public:
    std::vector<unsigned char> vchPubKey;

    CBLSPublicKey() {}
    explicit CBLSPublicKey(const std::vector<unsigned char>& vchPubKeyIn) : vchPubKey(vchPubKeyIn) {}

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vchPubKey);
    }

    bool IsValid() const { return vchPubKey.size() == BLS_PUBLIC_KEY_SIZE; }
    void SetNull() { vchPubKey.clear(); }
    
    bool operator==(const CBLSPublicKey& other) const {
        return vchPubKey == other.vchPubKey;
    }
    
    bool operator!=(const CBLSPublicKey& other) const {
        return !(*this == other);
    }
};

// BLS signature wrapper
class CBLSSignature {
public:
    std::vector<unsigned char> vchSig;

    CBLSSignature() {}
    explicit CBLSSignature(const std::vector<unsigned char>& vchSigIn) : vchSig(vchSigIn) {}

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vchSig);
    }

    bool IsValid() const { return vchSig.size() == BLS_SIGNATURE_SIZE; }
    void SetNull() { vchSig.clear(); }
    
    bool operator==(const CBLSSignature& other) const {
        return vchSig == other.vchSig;
    }
};

// Aggregated BLS signature with signer bitmap
class CBLSAggregateSignature {
public:
    std::vector<unsigned char> vchAggSig;
    uint32_t nSignerBitmap;  // Bitmap of which validators signed (up to 32)

    CBLSAggregateSignature() : nSignerBitmap(0) {}

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vchAggSig);
        READWRITE(nSignerBitmap);
    }

    bool IsValid() const { return vchAggSig.size() == BLS_SIGNATURE_SIZE; }
    void SetNull() { 
        vchAggSig.clear(); 
        nSignerBitmap = 0;
    }
    
    // Check if a specific validator signed (by index)
    bool HasSigner(int index) const { 
        if (index < 0 || index >= 32) return false;
        return (nSignerBitmap & (1 << index)) != 0; 
    }
    
    // Mark a validator as having signed
    void SetSigner(int index) { 
        if (index >= 0 && index < 32) {
            nSignerBitmap |= (1 << index);
        }
    }
    
    // Count number of signers
    int GetSignerCount() const {
        int count = 0;
        uint32_t bitmap = nSignerBitmap;
        while (bitmap) {
            count += bitmap & 1;
            bitmap >>= 1;
        }
        return count;
    }
    
    bool operator==(const CBLSAggregateSignature& other) const {
        return vchAggSig == other.vchAggSig && nSignerBitmap == other.nSignerBitmap;
    }
};

// BLS operations namespace
namespace BLS {
    // Generate a new random keypair
    bool GenerateKeypair(CBLSSecretKey& secretKey, CBLSPublicKey& publicKey);
    
    // Derive keypair from seed (for deterministic derivation from ECDSA key)
    bool DeriveFromSeed(const std::vector<unsigned char>& seed, CBLSSecretKey& secretKey, CBLSPublicKey& publicKey);
    
    // Sign a message
    bool Sign(const uint256& message, const CBLSSecretKey& secretKey, CBLSSignature& signature);
    
    // Verify a single signature
    bool Verify(const uint256& message, const CBLSPublicKey& publicKey, const CBLSSignature& signature);
    
    // Aggregate multiple signatures into one
    bool Aggregate(const std::vector<CBLSSignature>& signatures, CBLSAggregateSignature& aggregateSig);
    
    // Verify an aggregate signature
    bool VerifyAggregate(const uint256& message, 
                        const std::vector<CBLSPublicKey>& publicKeys,
                        const CBLSAggregateSignature& aggregateSig);
}

#endif // FLUX_CONSENSUS_BLS_H