// Copyright (c) 2024 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef FLUX_FLUXNODE_CONSENSUS_H
#define FLUX_FLUXNODE_CONSENSUS_H

#include "../primitives/block.h"
#include "../primitives/transaction.h"
#include "../fluxnode/fluxnode.h"
#include "../pubkey.h"
#include "../uint256.h"
#include "../serialize.h"
#include "../sync.h"
#include "../consensus/upgrades.h"
#include "../consensus/bls.h"
#include "../chainparams.h"

#include <vector>
#include <map>
#include <set>
#include <memory>

// Forward declarations
class CFluxnodeBlockProposal;

static const int FLUXNODE_CONSENSUS_QUORUM_SIZE = 21;
static const int FLUXNODE_CONSENSUS_QUORUM_PER_TIER = 7;
static const int FLUXNODE_CONSENSUS_THRESHOLD = 14; // 2/3 of 21
static const int FLUXNODE_BLOCK_INTERVAL = 30; // 30 seconds
static const int FLUXNODE_BLOCK_PRODUCTION_PHASE = 10; // 0-10 seconds
static const int FLUXNODE_VALIDATION_PHASE = 10; // 10-20 seconds
static const int FLUXNODE_FINALITY_PHASE = 10; // 20-30 seconds

// Fallback producer settings
static const int FLUXNODE_FALLBACK_PRODUCERS = 25; // Primary + 2 backups
static const int FLUXNODE_PRODUCER_SLOT_TIME = 10; // Each producer gets 10 seconds

// Fluxnode tiers for consensus
enum FluxnodeTier {
    TIER_CUMULUS = 1,
    TIER_NIMBUS = 2,
    TIER_STRATUS = 3
};

// Signature type for block signatures
enum SignatureType {
    SIG_TYPE_ECDSA = 0,
    SIG_TYPE_BLS = 1
};

// Block signature from a fluxnode
class CFluxnodeBlockSignature {
public:
    COutPoint fluxnodeOutpoint;
    int nTier;
    std::vector<unsigned char> vchSig;
    int64_t sigTime;
    uint8_t nSigType; // ECDSA or BLS

    CFluxnodeBlockSignature() : nTier(0), sigTime(0), nSigType(SIG_TYPE_ECDSA) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(fluxnodeOutpoint);
        READWRITE(nTier);
        READWRITE(vchSig);
        READWRITE(sigTime);
        // Only serialize sig type after BLS activation
        // Will be checked at runtime based on block height
        READWRITE(nSigType);
    }

    bool Sign(const uint256& blockHash, const CKey& key);
    bool SignBLS(const uint256& blockHash, const CBLSSecretKey& blsKey);
    bool Verify(const uint256& blockHash, const CPubKey& pubKey) const;
    bool VerifyBLS(const uint256& blockHash, const CBLSPublicKey& blsPubKey) const;
};

// Quorum certificate for block finality
class CQuorumCertificate {
public:
    uint256 blockHash;
    int nHeight;
    
    // Phase 1: Individual ECDSA signatures
    std::vector<CFluxnodeBlockSignature> signatures;
    
    // Phase 2: BLS aggregate signature
    std::vector<unsigned char> vchAggregateSignature;
    uint32_t nSignersBitmap; // Bitmap of which fluxnodes signed (for BLS)
    std::vector<COutPoint> signerOutpoints; // List of signers for BLS verification
    
    int64_t nTimeCreated;
    uint8_t nCertificateType; // ECDSA or BLS aggregate

    CQuorumCertificate() : nHeight(0), nTimeCreated(0), nSignersBitmap(0), nCertificateType(SIG_TYPE_ECDSA) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(blockHash);
        READWRITE(nHeight);
        
        // Serialize certificate type to determine format
        READWRITE(nCertificateType);
        
        if (nCertificateType == SIG_TYPE_BLS) {
            // BLS aggregate signature format
            READWRITE(vchAggregateSignature);
            READWRITE(nSignersBitmap);
            READWRITE(signerOutpoints);
        } else {
            // ECDSA individual signatures format
            READWRITE(signatures);
        }
        
        READWRITE(nTimeCreated);
    }

    bool HasQuorum() const;
    int GetTierWeightedScore() const;
    bool AddSignature(const CFluxnodeBlockSignature& sig);
    bool CreateBLSAggregate(const std::vector<CFluxnodeBlockSignature>& blsSigs);
    bool Validate(const uint256& expectedBlockHash) const;
};

// Consensus-specific data for fluxnodes (supplements FluxnodeCache)
struct FluxnodeConsensusData {
    double dReputationScore;
    int nConsecutiveMissedBlocks;
    int64_t nLastBlockProduced;
    
    FluxnodeConsensusData() :
        dReputationScore(1.0), 
        nConsecutiveMissedBlocks(0),
        nLastBlockProduced(0) {}
};

// Helper functions for checking consensus state
inline bool IsFluxnodeConsensusActive(int nHeight, const Consensus::Params& params) {
    return NetworkUpgradeActive(nHeight, params, Consensus::UPGRADE_FLUXNODE_QUORUM);
}

inline bool IsBLSActive(int nHeight, const Consensus::Params& params) {
    return NetworkUpgradeActive(nHeight, params, Consensus::UPGRADE_FLUXNODE_BLS);
}

// Main fluxnode consensus class
class CFluxnodeConsensus {
private:
    mutable CCriticalSection cs_consensus;
    
    // Consensus-specific data for fluxnodes (reputation, etc.)
    // FluxnodeCache has the main data, we only track consensus additions
    std::map<COutPoint, FluxnodeConsensusData> mapConsensusData;
    
    // Block producer schedule cache: height -> list of producers (primary + fallbacks)
    std::map<int, std::vector<COutPoint>> mapBlockProducersCache;
    
    // Validation quorum cache: height -> list of validators
    std::map<int, std::vector<COutPoint>> mapValidationQuorumCache;
    
    // Pending block proposals (not yet accepted)
    std::map<uint256, std::shared_ptr<CFluxnodeBlockProposal>> mapPendingProposals;
    
    // Pending signatures for blocks
    std::map<uint256, CQuorumCertificate> mapPendingQuorums;
    
    // Finalized blocks
    std::set<uint256> setFinalizedBlocks;

    // Calculate deterministic selection based on previous block
    std::vector<COutPoint> CalculateQuorum(const uint256& prevBlockHash, int nHeight, FluxnodeTier tier = TIER_CUMULUS, int nCount = FLUXNODE_CONSENSUS_QUORUM_PER_TIER);
    
public:
    CFluxnodeConsensus() {}
    
    // Initialize consensus with fluxnode list
    bool Initialize(int nHeight);
    
    // Block producer selection (with fallbacks)
    std::vector<COutPoint> GetBlockProducers(int nHeight, const uint256& blockHash, int nProducerCount = FLUXNODE_FALLBACK_PRODUCERS);
    bool IsBlockProducer(const COutPoint& outpoint, int nHeight, const uint256& prevBlockHash, int64_t nTime);
    int GetProducerIndex(const COutPoint& outpoint, int nHeight, const uint256& prevBlockHash);
    
    // Validation quorum
    std::vector<COutPoint> GetValidationQuorum(int nHeight, const uint256& blockHash);
    bool IsInValidationQuorum(const COutPoint& outpoint, int nHeight, const uint256& blockHash);
    
    // Block signing and verification
    bool SignBlock(CBlock& block, const CKey& key, const COutPoint& fluxnodeOutpoint, int nTier);
    bool VerifyBlockSignature(const CBlock& block, const CFluxnodeBlockSignature& signature);
    
    // Integration with ActiveFluxnode for key management
    bool SignBlockAsActiveNode(CBlock& block, int nHeight);  // Signs if we're the producer
    bool SignValidationAsActiveNode(const uint256& blockHash);  // Signs if we're in quorum
    
    // Quorum management
    bool AddBlockSignature(const uint256& blockHash, const CFluxnodeBlockSignature& signature);
    CQuorumCertificate GetQuorumCertificate(const uint256& blockHash);
    bool HasQuorum(const uint256& blockHash);
    
    // Block finality
    bool FinalizeBlock(const uint256& blockHash);
    bool IsBlockFinalized(const uint256& blockHash);
    
    // Pending proposal management
    void AddPendingProposal(const CFluxnodeBlockProposal& proposal);
    CFluxnodeBlockProposal GetPendingProposal(const uint256& blockHash) const;
    void RemovePendingProposal(const uint256& blockHash);
    
    // Fluxnode reputation management (LOCAL USE ONLY - NOT FOR CONSENSUS!)
    void UpdateFluxnodeReputation(const COutPoint& outpoint, bool bSuccess);
    double GetFluxnodeReputation(const COutPoint& outpoint) const;
    
    // Local decision functions (these can use reputation)
    bool ShouldRelayBlockFrom(const COutPoint& outpoint) const;
    bool ShouldAcceptConnectionFrom(const COutPoint& outpoint) const;
    
    // Schedule management
    void UpdateBlockProducerCache(int nHeight, const uint256& prevBlockHash);
    std::vector<COutPoint> GetUpcomingProducers(int nStartHeight, int nCount = 10);
    
    // Consensus state (queries FluxnodeCache)
    bool IsActive() const;
    int GetActiveFluxnodeCount() const;
    int GetActiveFluxnodeCount(int nTier) const;
    
    // Fork resolution
    int CompareForks(const CBlockIndex* pindex1, const CBlockIndex* pindex2);
    
    // Timing functions
    bool IsInProductionPhase(int64_t nTime, int nHeight);
    bool IsInValidationPhase(int64_t nTime, int nHeight);
    bool IsInFinalityPhase(int64_t nTime, int nHeight);
    int64_t GetPhaseStartTime(int nHeight, int nPhase);
};

extern CFluxnodeConsensus fluxnodeConsensus;

// Helper functions
FluxnodeTier GetFluxnodeTier(const CAmount& collateral);
int GetTierWeight(FluxnodeTier tier);
bool IsFluxnodeQuorumConsensusEnabled(int nHeight);

#endif // FLUX_FLUXNODE_CONSENSUS_H