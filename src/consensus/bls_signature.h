// Copyright (c) 2024 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef FLUX_BLS_SIGNATURE_H
#define FLUX_BLS_SIGNATURE_H

#include "../serialize.h"
#include "../uint256.h"
#include <vector>

// BLS signature sizes
static const size_t BLS_PUBLIC_KEY_SIZE = 48;
static const size_t BLS_SIGNATURE_SIZE = 96;
static const size_t BLS_AGGREGATE_SIGNATURE_SIZE = 96;

// BLS public key wrapper
class CBLSPublicKey {
private:
    std::vector<unsigned char> vchPubKey;

public:
    CBLSPublicKey() {}
    explicit CBLSPublicKey(const std::vector<unsigned char>& vchPubKeyIn) : vchPubKey(vchPubKeyIn) {}

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vchPubKey);
    }

    bool IsValid() const { return vchPubKey.size() == BLS_PUBLIC_KEY_SIZE; }
    const std::vector<unsigned char>& GetBytes() const { return vchPubKey; }
};

// BLS signature wrapper
class CBLSSignature {
private:
    std::vector<unsigned char> vchSig;

public:
    CBLSSignature() {}
    explicit CBLSSignature(const std::vector<unsigned char>& vchSigIn) : vchSig(vchSigIn) {}

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vchSig);
    }

    bool IsValid() const { return vchSig.size() == BLS_SIGNATURE_SIZE; }
    const std::vector<unsigned char>& GetBytes() const { return vchSig; }
};

// Aggregated BLS signature for quorum
class CBLSAggregateSignature {
private:
    std::vector<unsigned char> vchAggSig;
    uint32_t nSignerBitmap;  // Bitmap of which validators signed

public:
    CBLSAggregateSignature() : nSignerBitmap(0) {}

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vchAggSig);
        READWRITE(nSignerBitmap);
    }

    bool IsValid() const { return vchAggSig.size() == BLS_AGGREGATE_SIGNATURE_SIZE; }
    int GetSignerCount() const;
    bool HasSigner(int index) const { return (nSignerBitmap & (1 << index)) != 0; }
    void SetSigner(int index) { nSignerBitmap |= (1 << index); }
};

// BLS operations (to be implemented with actual BLS library)
namespace BLS {
    // Generate keypair
    bool GenerateKeypair(CBLSPublicKey& pubKey, std::vector<unsigned char>& privKey);
    
    // Sign message
    bool Sign(const uint256& message, const std::vector<unsigned char>& privKey, CBLSSignature& signature);
    
    // Verify single signature
    bool Verify(const uint256& message, const CBLSPublicKey& pubKey, const CBLSSignature& signature);
    
    // Aggregate multiple signatures
    bool Aggregate(const std::vector<CBLSSignature>& signatures, CBLSAggregateSignature& aggregateSig);
    
    // Verify aggregate signature
    bool VerifyAggregate(const uint256& message, 
                        const std::vector<CBLSPublicKey>& pubKeys,
                        const CBLSAggregateSignature& aggregateSig);
}

#endif // FLUX_BLS_SIGNATURE_H