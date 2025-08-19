// Copyright (c) 2024 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "fluxnode_consensus.h"
#include "fluxnode_messages.h"
#include "../hash.h"
#include "../main.h"
#include "../chainparams.h"
#include "../timedata.h"
#include "../util.h"
#include "../base58.h"
#include "../fluxnode/fluxnode.h"
#include "../fluxnode/fluxnodecachedb.h"
#include "../fluxnode/activefluxnode.h"
#include "../fluxnode/obfuscation.h"

#include <algorithm>
#include <random>

CFluxnodeConsensus fluxnodeConsensus;

// Helper functions implementation
FluxnodeTier GetFluxnodeTier(const CAmount& collateral) {
    if (collateral >= V2_FLUXNODE_COLLAT_STRATUS * COIN) {
        return TIER_STRATUS;
    } else if (collateral >= V2_FLUXNODE_COLLAT_NIMBUS * COIN) {
        return TIER_NIMBUS;
    } else if (collateral >= V2_FLUXNODE_COLLAT_CUMULUS * COIN) {
        return TIER_CUMULUS;
    }
    return TIER_CUMULUS;
}

int GetTierWeight(FluxnodeTier tier) {
    switch(tier) {
        case TIER_STRATUS: return 4;
        case TIER_NIMBUS: return 2;
        case TIER_CUMULUS: return 1;
        default: return 1;
    }
}

int GetQuorumWeightThreshold() {
    // Require weighted score of at least 21 (equivalent to 21 CUMULUS nodes)
    // This ensures proper representation across tiers
    return 21;
}

bool IsFluxnodeQuorumConsensusEnabled(int nHeight) {
    return NetworkUpgradeActive(nHeight, Params().GetConsensus(), Consensus::UPGRADE_FLUXNODE_QUORUM);
}

// CFluxnodeBlockSignature implementation
bool CFluxnodeBlockSignature::Sign(const uint256& blockHash, const CKey& key) {
    std::vector<unsigned char> vchSigTmp;
    if (!key.Sign(blockHash, vchSigTmp)) {
        return false;
    }
    vchSig = vchSigTmp;
    sigTime = GetAdjustedTime();
    return true;
}

bool CFluxnodeBlockSignature::Verify(const uint256& blockHash, const CPubKey& pubKey) const {
    return pubKey.Verify(blockHash, vchSig);
}

// CQuorumCertificate implementation
int CQuorumCertificate::GetTierWeightedScore() const {
    int score = 0;
    for (const auto& sig : signatures) {
        score += GetTierWeight(static_cast<FluxnodeTier>(sig.nTier));
    }
    return score;
}

bool CQuorumCertificate::AddSignature(const CFluxnodeBlockSignature& sig) {
    // Check if already have signature from this fluxnode
    for (const auto& existing : signatures) {
        if (existing.fluxnodeOutpoint == sig.fluxnodeOutpoint) {
            return false;
        }
    }
    signatures.push_back(sig);
    return true;
}

bool CQuorumCertificate::HasQuorum() const {
    if (nCertificateType == SIG_TYPE_BLS) {
        // For BLS, check the bitmap for signer count
        int signerCount = 0;
        uint32_t bitmap = nSignersBitmap;
        while (bitmap) {
            signerCount += bitmap & 1;
            bitmap >>= 1;
        }
        return signerCount >= FLUXNODE_CONSENSUS_THRESHOLD;
    } else {
        // For ECDSA, check signature count and weighted score
        if (signatures.size() < FLUXNODE_CONSENSUS_THRESHOLD) {
            return false;
        }
        
        // Also check tier-weighted score
        return GetTierWeightedScore() >= GetQuorumWeightThreshold();
    }
}

bool CQuorumCertificate::Validate(const uint256& expectedBlockHash) const {
    if (blockHash != expectedBlockHash) {
        return false;
    }
    
    // Verify we have enough signatures
    if (!HasQuorum()) {
        return false;
    }
    
    // Additional validation can be added here
    return true;
}

// CFluxnodeConsensus implementation
bool CFluxnodeConsensus::Initialize(int nHeight) {
    LOCK2(cs_consensus, g_fluxnodeCache.cs);
    
    // Initialize consensus-specific data for all confirmed fluxnodes
    mapConsensusData.clear();
    
    // Initialize reputation data for all confirmed nodes
    for (const auto& node : g_fluxnodeCache.mapConfirmedFluxnodeData) {
        // Only initialize consensus data, the rest is in FluxnodeCache
        mapConsensusData[node.first] = FluxnodeConsensusData();
    }
    
    LogPrintf("CFluxnodeConsensus: Initialized with %d fluxnodes at height %d\n",
              g_fluxnodeCache.mapConfirmedFluxnodeData.size(), nHeight);
    
    return g_fluxnodeCache.mapConfirmedFluxnodeData.size() > 0;
}

std::vector<COutPoint> CFluxnodeConsensus::CalculateQuorum(const uint256& prevBlockHash, int nHeight, FluxnodeTier tier, int nCount) {
    std::vector<COutPoint> vResult;
    std::vector<std::pair<uint256, COutPoint>> vSortedNodes;
    
    LOCK2(cs_consensus, g_fluxnodeCache.cs);
    
    // CRITICAL: Quorum selection MUST be deterministic across all nodes
    // DO NOT use local reputation or any non-deterministic data here
    // All nodes must calculate the exact same quorum for consensus to work
    
    // Filter nodes by tier from FluxnodeCache
    for (const auto& pair : g_fluxnodeCache.mapConfirmedFluxnodeData) {
        const FluxnodeCacheData& nodeData = pair.second;
        
        // Check tier match (Cumulus=1, Nimbus=2, Stratus=3 matches our enum)
        if (tier == TIER_CUMULUS || nodeData.nTier == tier) {
            // Calculate deterministic hash for this node
            CHashWriter hasher(SER_GETHASH, 0);
            hasher << prevBlockHash;
            hasher << pair.first;
            hasher << nHeight;
            uint256 nodeHash = hasher.GetHash();
            
            // NO REPUTATION CHECK - must be deterministic!
            // All confirmed nodes are eligible for quorum
            vSortedNodes.push_back(std::make_pair(nodeHash, pair.first));
        }
    }
    
    // Sort by hash for deterministic selection
    std::sort(vSortedNodes.begin(), vSortedNodes.end());
    
    // Select top nCount nodes
    for (size_t i = 0; i < vSortedNodes.size() && vResult.size() < nCount; i++) {
        vResult.push_back(vSortedNodes[i].second);
    }
    
    return vResult;
}

std::vector<COutPoint> CFluxnodeConsensus::GetBlockProducers(int nHeight, const uint256& blockHash, int nProducerCount) {
    LOCK2(cs_consensus, g_fluxnodeCache.cs);
    
    // Check cache first
    auto it = mapBlockProducersCache.find(nHeight);
    if (it != mapBlockProducersCache.end()) {
        return it->second;
    }
    
    // CRITICAL: Use historical snapshot for deterministic consensus
    // This ensures all nodes use the same fluxnode list
    
    std::map<COutPoint, FluxnodeCacheData> mapHistoricalData;
    uint256 hashForSelection = blockHash; // Default to provided hash
    
    // Try to get snapshot data
    bool fUsingSnapshot = false;
    if (nHeight > FLUXNODE_SNAPSHOT_INTERVAL) {
        // Look back to find reference height for snapshot
        int nReferenceHeight = (nHeight / FLUXNODE_SNAPSHOT_INTERVAL) * FLUXNODE_SNAPSHOT_INTERVAL;
        
        // Get snapshot through FluxnodeCache (it handles the DB read internally)
        FluxnodeSnapshot snapshot;
        if (g_fluxnodeCache.GetSnapshotForHeight(nReferenceHeight, snapshot)) {
            mapHistoricalData = snapshot.mapFluxnodeData;
            hashForSelection = snapshot.blockHash; // Use snapshot's block hash for entire interval!
            fUsingSnapshot = true;
            LogPrint("fluxnode", "Using snapshot from height %d (hash %s) for producer selection at height %d\n",
                    nReferenceHeight, hashForSelection.ToString(), nHeight);
        }
    }
    
    // Fallback to current cache if no snapshot available (early blocks)
    // TODO - FLUXNODE - Should this even be possible?? Just fail here. bad blockchian state?
    if (!fUsingSnapshot) {
        mapHistoricalData = g_fluxnodeCache.mapConfirmedFluxnodeData;
        LogPrint("fluxnode", "No snapshot available, using current cache for height %d\n", nHeight);
    }
    
    std::vector<std::pair<uint256, COutPoint>> vWeightedNodes;
    
    for (const auto& pair : mapHistoricalData) {
        const FluxnodeCacheData& nodeData = pair.second;
        int weight = GetTierWeight(static_cast<FluxnodeTier>(nodeData.nTier));
        
        // NO REPUTATION CHECK - must be deterministic!
        // All confirmed nodes in the snapshot are eligible

        // Add multiple entries based on weight
        for (int w = 0; w < weight; w++) {
            CHashWriter hasher(SER_GETHASH, 0);
            hasher << hashForSelection;  // Use snapshot hash for determinism
            hasher << pair.first;
            hasher << nHeight;  // Height changes, ensuring different producers per block
            hasher << w; // Include weight index for uniqueness
            uint256 nodeHash = hasher.GetHash();
            vWeightedNodes.push_back(std::make_pair(nodeHash, pair.first));
        }
    }
    
    std::vector<COutPoint> vProducers;
    
    if (vWeightedNodes.empty()) {
        return vProducers;
    }
    
    // Sort for deterministic selection
    std::sort(vWeightedNodes.begin(), vWeightedNodes.end());
    
    // Select multiple producers (primary + fallbacks)
    int baseIndex = nHeight % vWeightedNodes.size();
    for (int i = 0; i < nProducerCount && i < vWeightedNodes.size(); i++) {
        int index = (baseIndex + i) % vWeightedNodes.size();
        vProducers.push_back(vWeightedNodes[index].second);
    }
    
    // Cache the result for future lookups
    mapBlockProducersCache[nHeight] = vProducers;
    
    return vProducers;
}

bool CFluxnodeConsensus::IsBlockProducer(const COutPoint& outpoint, int nHeight, const uint256& prevBlockHash, int64_t nTime) {
    std::vector<COutPoint> vProducers = GetBlockProducers(nHeight, prevBlockHash, FLUXNODE_FALLBACK_PRODUCERS);
    
    // Calculate which time slot we're in based on block time
    int64_t nBlockStartTime = nHeight * FLUXNODE_BLOCK_INTERVAL;
    int64_t nTimeOffset = nTime - nBlockStartTime;
    
    // Each producer gets FLUXNODE_PRODUCER_SLOT_TIME seconds
    for (size_t i = 0; i < vProducers.size(); i++) {
        if (vProducers[i] == outpoint) {
            int64_t nSlotStart = i * FLUXNODE_PRODUCER_SLOT_TIME;
            int64_t nSlotEnd = nSlotStart + FLUXNODE_PRODUCER_SLOT_TIME;
            
            // Check if current time is within this producer's time window
            if (nTimeOffset >= nSlotStart && nTimeOffset < nSlotEnd) {
                LogPrint("fluxnode", "Node %s is producer %d for height %d (slot %d-%d seconds)\n",
                         outpoint.ToString(), i, nHeight, nSlotStart, nSlotEnd);
                return true;
            }
        }
    }
    
    return false;
}

int CFluxnodeConsensus::GetProducerIndex(const COutPoint& outpoint, int nHeight, const uint256& prevBlockHash) {
    std::vector<COutPoint> vProducers = GetBlockProducers(nHeight, prevBlockHash, FLUXNODE_FALLBACK_PRODUCERS);
    
    for (size_t i = 0; i < vProducers.size(); i++) {
        if (vProducers[i] == outpoint) {
            return i;
        }
    }
    
    return -1; // Not a producer for this height
}

std::vector<COutPoint> CFluxnodeConsensus::GetValidationQuorum(int nHeight, const uint256& blockHash) {
    LOCK2(cs_consensus, g_fluxnodeCache.cs);
    
    // Check if we have a cached quorum for this height
    auto it = mapValidationQuorumCache.find(nHeight);
    if (it != mapValidationQuorumCache.end()) {
        return it->second;
    }
    
    std::vector<COutPoint> vQuorum;
    
    // CRITICAL: Use snapshot data and snapshot block hash for deterministic consensus
    std::map<COutPoint, FluxnodeCacheData> mapHistoricalData;
    uint256 hashForQuorum = blockHash; // Default to provided hash
    bool fUsingSnapshot = false;
    
    if (nHeight > FLUXNODE_SNAPSHOT_INTERVAL) {
        // Get the snapshot for this interval
        int nReferenceHeight = (nHeight / FLUXNODE_SNAPSHOT_INTERVAL) * FLUXNODE_SNAPSHOT_INTERVAL;
        
        // Get snapshot through FluxnodeCache (it handles the DB read internally)
        FluxnodeSnapshot snapshot;
        if (g_fluxnodeCache.GetSnapshotForHeight(nReferenceHeight, snapshot)) {
            mapHistoricalData = snapshot.mapFluxnodeData;
            hashForQuorum = snapshot.blockHash; // Use snapshot's block hash for entire interval!
            fUsingSnapshot = true;
            LogPrint("fluxnode", "Using snapshot from height %d (hash %s) for quorum at height %d\n",
                     nReferenceHeight, hashForQuorum.ToString(), nHeight);
        }
    }

    // TODO - FLUXNODE (WHAT DO IT HERE, if we don't have snapshot?? Is this even possible?
    if (!fUsingSnapshot) {
        // Fallback to current data (only for early blocks or if snapshot fails)
        mapHistoricalData = g_fluxnodeCache.mapConfirmedFluxnodeData;
        LogPrint("fluxnode", "No snapshot available, using current cache for quorum at height %d\n", nHeight);
    }
    
    // Calculate quorum from snapshot data
    std::vector<std::pair<uint256, COutPoint>> vSortedNodes[3]; // One for each tier
    
    for (const auto& pair : mapHistoricalData) {
        const FluxnodeCacheData& nodeData = pair.second;
        int tierIndex = nodeData.nTier - 1; // Convert to 0-based index
        
        if (tierIndex >= 0 && tierIndex < 3) {
            CHashWriter hasher(SER_GETHASH, 0);
            hasher << hashForQuorum;  // Use snapshot hash for determinism
            hasher << pair.first;
            hasher << nHeight;  // Height still changes, ensuring different quorum per block
            uint256 nodeHash = hasher.GetHash();
            vSortedNodes[tierIndex].push_back(std::make_pair(nodeHash, pair.first));
        }
    }
    
    // Sort each tier and select top 7
    for (int tier = 0; tier < 3; tier++) {
        std::sort(vSortedNodes[tier].begin(), vSortedNodes[tier].end());
        for (size_t i = 0; i < FLUXNODE_CONSENSUS_QUORUM_PER_TIER && i < vSortedNodes[tier].size(); i++) {
            vQuorum.push_back(vSortedNodes[tier][i].second);
        }
    }
    
    // Cache the result
    mapValidationQuorumCache[nHeight] = vQuorum;
    
    return vQuorum;
}

bool CFluxnodeConsensus::IsInValidationQuorum(const COutPoint& outpoint, int nHeight, const uint256& blockHash) {
    std::vector<COutPoint> vQuorum = GetValidationQuorum(nHeight, blockHash);
    return std::find(vQuorum.begin(), vQuorum.end(), outpoint) != vQuorum.end();
}

bool CFluxnodeConsensus::SignBlock(CBlock& block, const CKey& key, const COutPoint& fluxnodeOutpoint, int nTier) {
    CFluxnodeBlockSignature signature;
    signature.fluxnodeOutpoint = fluxnodeOutpoint;
    signature.nTier = nTier;
    
    uint256 blockHash = block.GetHash();
    if (!signature.Sign(blockHash, key)) {
        return false;
    }
    
    // Serialize signature and store in block
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << signature;
    block.vchProducerSig = std::vector<unsigned char>(ss.begin(), ss.end());
    
    return true;
}

bool CFluxnodeConsensus::SignBlockAsActiveNode(CBlock& block, int nHeight) {
    // Check if we're running as an active fluxnode
    if (!activeFluxnode.deterministicOutPoint.IsNull()) {
        // Check if we're the block producer for this height
        if (!IsBlockProducer(activeFluxnode.deterministicOutPoint, nHeight, 
                            block.hashPrevBlock, block.GetBlockTime())) {
            LogPrint("fluxnode", "Not the block producer for height %d\n", nHeight);
            return false;
        }
        
        // Get our node's tier
        int nTier = 0;
        {
            LOCK(g_fluxnodeCache.cs);
            auto it = g_fluxnodeCache.mapConfirmedFluxnodeData.find(activeFluxnode.deterministicOutPoint);
            if (it != g_fluxnodeCache.mapConfirmedFluxnodeData.end()) {
                nTier = it->second.nTier;
            } else {
                LogPrintf("Error: Active node not found in confirmed data\n");
                return false;
            }
        }
        
        // Get the private key using the global fluxnode key
        CKey key;
        CPubKey pubkey;
        std::string errorMessage;
        
        if (!obfuScationSigner.SetKey(strFluxnodePrivKey, errorMessage, key, pubkey)) {
            LogPrintf("Error: Cannot retrieve fluxnode private key for signing: %s\n", errorMessage);
            return false;
        }
        
        // Sign the block
        if (!SignBlock(block, key, activeFluxnode.deterministicOutPoint, nTier)) {
            LogPrintf("Error: Failed to sign block at height %d\n", nHeight);
            return false;
        }
        
        LogPrintf("Successfully signed block at height %d as producer %s\n", 
                 nHeight, activeFluxnode.deterministicOutPoint.ToString());
        return true;
    }
    
    return false;
}

bool CFluxnodeConsensus::SignValidationAsActiveNode(const uint256& blockHash) {
    // Check if we're running as an active fluxnode
    if (!activeFluxnode.deterministicOutPoint.IsNull()) {
        // TODO: Get block height from block index
        // For now, we need to look up the block to get its height
        // This would need access to mapBlockIndex or the block itself
        
        // Get our node's tier
        int nTier = 0;
        {
            LOCK(g_fluxnodeCache.cs);
            auto it = g_fluxnodeCache.mapConfirmedFluxnodeData.find(activeFluxnode.deterministicOutPoint);
            if (it != g_fluxnodeCache.mapConfirmedFluxnodeData.end()) {
                nTier = it->second.nTier;
            } else {
                return false;
            }
        }
        
        // Get the private key using the global fluxnode key
        CKey key;
        CPubKey pubkey;
        std::string errorMessage;
        
        if (!obfuScationSigner.SetKey(strFluxnodePrivKey, errorMessage, key, pubkey)) {
            LogPrintf("Error: Cannot retrieve fluxnode private key for validation signing: %s\n", errorMessage);
            return false;
        }
        
        // Create and sign validation signature
        CFluxnodeBlockSignature signature;
        signature.fluxnodeOutpoint = activeFluxnode.deterministicOutPoint;
        signature.nTier = nTier;
        
        if (!signature.Sign(blockHash, key)) {
            LogPrintf("Error: Failed to sign validation for block %s\n", blockHash.ToString());
            return false;
        }
        
        // Add to pending quorum
        if (!AddBlockSignature(blockHash, signature)) {
            LogPrintf("Error: Failed to add signature to quorum for block %s\n", blockHash.ToString());
            return false;
        }
        
        LogPrintf("Successfully signed validation for block %s\n", blockHash.ToString());
        return true;
    }
    
    return false;
}

bool CFluxnodeConsensus::VerifyBlockSignature(const CBlock& block, const CFluxnodeBlockSignature& signature) {
    LOCK2(cs_consensus, g_fluxnodeCache.cs);

    
    // Find fluxnode info in FluxnodeCache
    auto it = g_fluxnodeCache.mapConfirmedFluxnodeData.find(signature.fluxnodeOutpoint);
    if (it == g_fluxnodeCache.mapConfirmedFluxnodeData.end()) {
        return false;
    }
    
    // Verify signature using public key from cache
    uint256 blockHash = block.GetHash();
    return signature.Verify(blockHash, it->second.pubKey);
}

bool CFluxnodeConsensus::AddBlockSignature(const uint256& blockHash, const CFluxnodeBlockSignature& signature) {
    LOCK(cs_consensus);
    
    // Get or create quorum certificate
    CQuorumCertificate& cert = mapPendingQuorums[blockHash];
    cert.blockHash = blockHash;
    
    // Add signature
    return cert.AddSignature(signature);
}

CQuorumCertificate CFluxnodeConsensus::GetQuorumCertificate(const uint256& blockHash) {
    LOCK(cs_consensus);
    
    auto it = mapPendingQuorums.find(blockHash);
    if (it != mapPendingQuorums.end()) {
        return it->second;
    }
    
    return CQuorumCertificate();
}

bool CFluxnodeConsensus::HasQuorum(const uint256& blockHash) {
    LOCK(cs_consensus);
    
    auto it = mapPendingQuorums.find(blockHash);
    if (it != mapPendingQuorums.end()) {
        return it->second.HasQuorum();
    }
    
    return false;
}

bool CFluxnodeConsensus::FinalizeBlock(const uint256& blockHash) {
    LOCK(cs_consensus);
    
    if (!HasQuorum(blockHash)) {
        return false;
    }
    
    setFinalizedBlocks.insert(blockHash);
    
    // Clean up old pending quorums
    if (mapPendingQuorums.size() > 100) {
        // Keep only recent quorums
        std::vector<uint256> vToRemove;
        for (const auto& pair : mapPendingQuorums) {
            if (setFinalizedBlocks.count(pair.first)) {
                vToRemove.push_back(pair.first);
            }
        }
        
        for (const auto& hash : vToRemove) {
            mapPendingQuorums.erase(hash);
        }
    }
    
    return true;
}

bool CFluxnodeConsensus::IsBlockFinalized(const uint256& blockHash) {
    LOCK(cs_consensus);
    return setFinalizedBlocks.count(blockHash) > 0;
}

void CFluxnodeConsensus::UpdateFluxnodeReputation(const COutPoint& outpoint, bool bSuccess) {
    LOCK(cs_consensus);
    
    // Initialize consensus data if it doesn't exist
    if (mapConsensusData.find(outpoint) == mapConsensusData.end()) {
        mapConsensusData[outpoint] = FluxnodeConsensusData();
    }
    
    FluxnodeConsensusData& data = mapConsensusData[outpoint];
    
    if (bSuccess) {
        // Reset consecutive misses and improve reputation
        data.nConsecutiveMissedBlocks = 0;
        data.dReputationScore = std::min(2.0, data.dReputationScore * 1.01);
        data.nLastBlockProduced = GetAdjustedTime();
    } else {
        // Increase consecutive misses and decrease reputation
        data.nConsecutiveMissedBlocks++;
        data.dReputationScore = std::max(0.1, data.dReputationScore * 0.95);
        
        // Severe penalty for multiple consecutive misses
        if (data.nConsecutiveMissedBlocks > 3) {
            data.dReputationScore *= 0.8;
        }
    }
}

double CFluxnodeConsensus::GetFluxnodeReputation(const COutPoint& outpoint) const {
    LOCK(cs_consensus);
    
    auto it = mapConsensusData.find(outpoint);
    if (it != mapConsensusData.end()) {
        return it->second.dReputationScore;
    }
    
    // Default reputation for nodes we haven't tracked yet
    return 1.0;
}

// LOCAL DECISION FUNCTIONS - These can use reputation without breaking consensus
// These are node-specific decisions that don't need network agreement

bool CFluxnodeConsensus::ShouldRelayBlockFrom(const COutPoint& outpoint) const {

    return true;
    // TODO - FLUXNODE - If we want something like this.

//    // Local decision: Don't relay blocks from nodes with terrible reputation
//    // This doesn't affect consensus - other nodes might relay it
//    double reputation = GetFluxnodeReputation(outpoint);
//
//    if (reputation < 0.2) {
//        LogPrint("fluxnode", "Not relaying block from low reputation node %s (rep: %.2f)\n",
//                 outpoint.ToString(), reputation);
//        return false;
//    }
//
//    return true;
}

bool CFluxnodeConsensus::ShouldAcceptConnectionFrom(const COutPoint& outpoint) const {

    return true;
    // TODO - FLUXNODE - If we want something like this.

//    // Local decision: Might disconnect from very bad reputation nodes
//    // This is just connection management, not consensus
//    double reputation = GetFluxnodeReputation(outpoint);
//
//    if (reputation < 0.1) {
//        LogPrint("fluxnode", "Rejecting connection from very low reputation node %s (rep: %.2f)\n",
//                 outpoint.ToString(), reputation);
//        return false;
//    }
//
//    return true;
}

void CFluxnodeConsensus::UpdateBlockProducerCache(int nHeight, const uint256& prevBlockHash) {
    LOCK(cs_consensus);
    
    // Clear old cached entries that are too far in the past
    auto it = mapBlockProducersCache.begin();
    while (it != mapBlockProducersCache.end()) {
        if (it->first < nHeight - 100) {  // Keep last 100 blocks for debugging
            it = mapBlockProducersCache.erase(it);
        } else {
            ++it;
        }
    }
    
    // Also clean up old quorum cache
    auto qit = mapValidationQuorumCache.begin();
    while (qit != mapValidationQuorumCache.end()) {
        if (qit->first < nHeight - 100) {
            qit = mapValidationQuorumCache.erase(qit);
        } else {
            ++qit;
        }
    }
    
    // Calculate how many blocks until next snapshot
    int nNextSnapshotHeight = ((nHeight / FLUXNODE_SNAPSHOT_INTERVAL) + 1) * FLUXNODE_SNAPSHOT_INTERVAL;
    int nBlocksToCalculate = nNextSnapshotHeight - nHeight;
    
    LogPrint("fluxnode", "Pre-calculating block producers and quorums from height %d to %d (next snapshot at %d)\n",
             nHeight + 1, nHeight + nBlocksToCalculate, nNextSnapshotHeight);
    
    // Generate schedule for blocks until next snapshot
    for (int h = nHeight + 1; h <= nHeight + nBlocksToCalculate; h++) {
        // Pre-calculate block producers if not already cached
        if (mapBlockProducersCache.find(h) == mapBlockProducersCache.end()) {
            std::vector<COutPoint> producers = GetBlockProducers(h, prevBlockHash, FLUXNODE_FALLBACK_PRODUCERS);
            mapBlockProducersCache[h] = producers;
        }
        
        // Pre-calculate validation quorums if not already cached
        // Note: We pass prevBlockHash as a dummy here since GetValidationQuorum will use snapshot hash
        if (mapValidationQuorumCache.find(h) == mapValidationQuorumCache.end()) {
            GetValidationQuorum(h, prevBlockHash); // This will cache the result
        }
    }
}

std::vector<COutPoint> CFluxnodeConsensus::GetUpcomingProducers(int nStartHeight, int nCount) {
    LOCK(cs_consensus);
    
    std::vector<COutPoint> vResult;
    
    // Simply look up each height in our cache
    for (int h = nStartHeight; h < nStartHeight + nCount; h++) {
        auto it = mapBlockProducersCache.find(h);
        if (it != mapBlockProducersCache.end()) {
            // Add all producers for this height
            vResult.insert(vResult.end(), it->second.begin(), it->second.end());
        }
    }
    
    return vResult;
}

bool CFluxnodeConsensus::IsActive() const {
    LOCK2(cs_consensus, g_fluxnodeCache.cs);
    return g_fluxnodeCache.mapConfirmedFluxnodeData.size() >= FLUXNODE_CONSENSUS_QUORUM_SIZE;
}

int CFluxnodeConsensus::GetActiveFluxnodeCount() const {
    LOCK2(cs_consensus, g_fluxnodeCache.cs);
    return g_fluxnodeCache.mapConfirmedFluxnodeData.size();
}

int CFluxnodeConsensus::GetActiveFluxnodeCount(int nTier) const {
    LOCK2(cs_consensus, g_fluxnodeCache.cs);
    
    int count = 0;
    for (const auto& pair : g_fluxnodeCache.mapConfirmedFluxnodeData) {
        if (pair.second.nTier == nTier) {
            count++;
        }
    }
    return count;
}

int CFluxnodeConsensus::CompareForks(const CBlockIndex* pindex1, const CBlockIndex* pindex2) {
    // Compare two forks based on finalized blocks and weighted signatures
    
    int score1 = 0, score2 = 0;
    
    // Walk back and count finalized blocks
    const CBlockIndex* p1 = pindex1;
    const CBlockIndex* p2 = pindex2;
    
    for (int i = 0; i < 100 && p1; i++, p1 = p1->pprev) {
        if (IsBlockFinalized(p1->GetBlockHash())) {
            score1 += 10;
        }
    }
    
    for (int i = 0; i < 100 && p2; i++, p2 = p2->pprev) {
        if (IsBlockFinalized(p2->GetBlockHash())) {
            score2 += 10;
        }
    }
    
    if (score1 > score2) return 1;
    if (score2 > score1) return -1;
    
    // If equal, use chain work
    if (pindex1->nChainWork > pindex2->nChainWork) return 1;
    if (pindex2->nChainWork > pindex1->nChainWork) return -1;
    
    return 0;
}

bool CFluxnodeConsensus::IsInProductionPhase(int64_t nTime, int nHeight) {
    int64_t blockStartTime = GetPhaseStartTime(nHeight, 0);
    int64_t phaseEndTime = blockStartTime + FLUXNODE_BLOCK_PRODUCTION_PHASE;
    return nTime >= blockStartTime && nTime < phaseEndTime;
}

bool CFluxnodeConsensus::IsInValidationPhase(int64_t nTime, int nHeight) {
    int64_t phaseStartTime = GetPhaseStartTime(nHeight, 1);
    int64_t phaseEndTime = phaseStartTime + FLUXNODE_VALIDATION_PHASE;
    return nTime >= phaseStartTime && nTime < phaseEndTime;
}

bool CFluxnodeConsensus::IsInFinalityPhase(int64_t nTime, int nHeight) {
    int64_t phaseStartTime = GetPhaseStartTime(nHeight, 2);
    int64_t phaseEndTime = phaseStartTime + FLUXNODE_FINALITY_PHASE;
    return nTime >= phaseStartTime && nTime < phaseEndTime;
}

int64_t CFluxnodeConsensus::GetPhaseStartTime(int nHeight, int nPhase) {
    // Calculate the expected time for this block height
    // Assuming genesis at time 0 for simplicity (should use actual genesis time)
    int64_t blockTime = nHeight * FLUXNODE_BLOCK_INTERVAL;
    
    switch(nPhase) {
        case 0: // Production phase
            return blockTime;
        case 1: // Validation phase
            return blockTime + FLUXNODE_BLOCK_PRODUCTION_PHASE;
        case 2: // Finality phase
            return blockTime + FLUXNODE_BLOCK_PRODUCTION_PHASE + FLUXNODE_VALIDATION_PHASE;
        default:
            return blockTime;
    }
}

// Pending proposal management methods
void CFluxnodeConsensus::AddPendingProposal(const CFluxnodeBlockProposal& proposal) {
    LOCK(cs_consensus);
    uint256 blockHash = proposal.block.GetHash();
    mapPendingProposals[blockHash] = std::make_shared<CFluxnodeBlockProposal>(proposal);
    LogPrint("fluxnode", "Added pending proposal for block %s\n", blockHash.ToString());
}

CFluxnodeBlockProposal CFluxnodeConsensus::GetPendingProposal(const uint256& blockHash) const {
    LOCK(cs_consensus);
    auto it = mapPendingProposals.find(blockHash);
    if (it != mapPendingProposals.end() && it->second) {
        return *(it->second);
    }
    return CFluxnodeBlockProposal();
}

void CFluxnodeConsensus::RemovePendingProposal(const uint256& blockHash) {
    LOCK(cs_consensus);
    mapPendingProposals.erase(blockHash);
    LogPrint("fluxnode", "Removed pending proposal for block %s\n", blockHash.ToString());
}