// Copyright (c) 2024 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef FLUX_FLUXNODE_MESSAGES_H
#define FLUX_FLUXNODE_MESSAGES_H

#include "../net.h"
#include "../protocol.h"
#include "../serialize.h"
#include "../uint256.h"
#include "../primitives/block.h"
#include "../primitives/transaction.h"

// Forward declarations
class CFluxnodeBlockSignature;
class CQuorumCertificate;
class CValidationState;
class CKey;
class CPubKey;

// P2P message types for fluxnode consensus
static const char* MNBLOCKPROPOSAL = "mnblockprop";
static const char* MNBLOCKSIG = "mnblocksig";
static const char* MNQUORUMCERT = "mnquorumcert";
static const char* MNFINALBLOCK = "mnfinalblock";

// Block proposal message from block producer
class CFluxnodeBlockProposal {
public:
    CBlock block;
    COutPoint producerOutpoint;
    std::vector<unsigned char> vchProducerSig;
    int64_t nTimeProposed;

    CFluxnodeBlockProposal() : nTimeProposed(0) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(block);
        READWRITE(producerOutpoint);
        READWRITE(vchProducerSig);
        READWRITE(nTimeProposed);
    }

    uint256 GetHash() const { return block.GetHash(); }
    bool Sign(const CKey& key);
    bool Verify(const CPubKey& pubKey) const;
};

// Block signature message from validation quorum member
class CFluxnodeBlockSigMessage {
public:
    uint256 blockHash;
    int nHeight;
    // We'll store the signature data directly to avoid circular dependency
    COutPoint fluxnodeOutpoint;
    int nTier;
    std::vector<unsigned char> vchSig;
    int64_t sigTime;
    uint8_t nSigType; // ECDSA or BLS

    CFluxnodeBlockSigMessage() : nHeight(0), nTier(0), sigTime(0), nSigType(0) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(blockHash);
        READWRITE(nHeight);
        READWRITE(fluxnodeOutpoint);
        READWRITE(nTier);
        READWRITE(vchSig);
        READWRITE(sigTime);
        READWRITE(nSigType);
    }
};

// Quorum certificate broadcast message
class CFluxnodeQuorumCertMessage {
public:
    // Store certificate data directly to avoid circular dependency
    uint256 blockHash;
    int nHeight;
    uint8_t nCertificateType; // ECDSA or BLS aggregate
    
    // For ECDSA certificates
    std::vector<CFluxnodeBlockSigMessage> signatures;
    
    // For BLS certificates
    std::vector<unsigned char> vchAggregateSignature;
    uint32_t nSignersBitmap;
    std::vector<COutPoint> signerOutpoints;
    
    int64_t nTimeCreated;

    CFluxnodeQuorumCertMessage() : nHeight(0), nCertificateType(0), nSignersBitmap(0), nTimeCreated(0) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(blockHash);
        READWRITE(nHeight);
        READWRITE(nCertificateType);
        
        if (nCertificateType == 1) { // BLS
            READWRITE(vchAggregateSignature);
            READWRITE(nSignersBitmap);
            READWRITE(signerOutpoints);
        } else { // ECDSA
            READWRITE(signatures);
        }
        
        READWRITE(nTimeCreated);
    }
};



// Message processing functions
bool ProcessFluxnodeBlockProposal(CNode* pfrom, const CFluxnodeBlockProposal& proposal, CValidationState& state);
bool ProcessFluxnodeBlockSig(CNode* pfrom, const CFluxnodeBlockSigMessage& sigMsg, CValidationState& state);
bool ProcessFluxnodeQuorumCert(CNode* pfrom, const CFluxnodeQuorumCertMessage& certMsg, CValidationState& state);

// Message sending functions
void BroadcastFluxnodeBlockProposal(const CFluxnodeBlockProposal& proposal);
void BroadcastFluxnodeBlockSignature(const uint256& blockHash, const CFluxnodeBlockSigMessage& sigMsg);
void BroadcastQuorumCertificate(const CFluxnodeQuorumCertMessage& certMsg);

// Relay functions
void RelayFluxnodeBlockProposal(const CFluxnodeBlockProposal& proposal);
void RelayFluxnodeBlockSignature(const CFluxnodeBlockSigMessage& sigMsg);
void RelayQuorumCertificate(const CFluxnodeQuorumCertMessage& certMsg);

#endif // FLUX_FLUXNODE_MESSAGES_H