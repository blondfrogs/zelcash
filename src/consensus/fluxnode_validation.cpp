// Copyright (c) 2024 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "fluxnode_consensus.h"
#include "validation.h"
#include "../main.h"
#include "../chainparams.h"
#include "../timedata.h"
#include "../util.h"
#include "../fluxnode/fluxnodecachedb.h"
#include "bls.h"

// Forward declaration
bool VerifyBLSQuorumCertificate(const CQuorumCertificate& quorumCert, const uint256& blockHash);

// Check if block header is valid under fluxnode consensus
bool CheckFluxnodeBlockHeader(
    const CBlockHeader& block,
    CValidationState& state,
    const CChainParams& chainparams,
    int nHeight)
{
    // Skip if fluxnode consensus not active
    if (!IsFluxnodeQuorumConsensusEnabled(nHeight)) {
        return true;
    }
    
    // Check block version for fluxnode consensus
    if (block.nVersion < 5) {
        return state.DoS(100, error("CheckFluxnodeBlockHeader(): block version too low for fluxnode consensus"),
                         REJECT_INVALID, "bad-version");
    }
    
    // Fluxnode blocks don't need POW
    // But we still check timestamp for future
    if (block.GetBlockTime() > GetAdjustedTime() + FLUXNODE_BLOCK_INTERVAL * 2) {
        return state.Invalid(error("CheckFluxnodeBlockHeader(): block timestamp too far in the future"),
                             REJECT_INVALID, "time-too-new");
    }
    
    return true;
}

// Check if block is valid under fluxnode consensus
bool CheckFluxnodeBlock(
    const CBlock& block,
    CValidationState& state,
    const CChainParams& chainparams,
    CBlockIndex* pindexPrev)
{
    int nHeight = pindexPrev ? pindexPrev->nHeight + 1 : 0;
    
    // Skip if fluxnode consensus not active
    if (!IsFluxnodeQuorumConsensusEnabled(nHeight)) {
        return true;
    }
    
    // Verify block producer signature exists
    if (block.vchProducerSig.empty()) {
        return state.DoS(100, error("CheckFluxnodeBlock(): missing block producer signature"),
                         REJECT_INVALID, "bad-producer-sig-missing");
    }
    
    // Deserialize and verify producer signature
    CDataStream ssProducer(block.vchProducerSig, SER_NETWORK, PROTOCOL_VERSION);
    CFluxnodeBlockSignature producerSig;
    try {
        ssProducer >> producerSig;
    } catch (const std::exception& e) {
        return state.DoS(100, error("CheckFluxnodeBlock(): failed to deserialize producer signature"),
                         REJECT_INVALID, "bad-producer-sig-format");
    }
    
    // Verify this fluxnode was the designated block producer
    uint256 prevBlockHash = pindexPrev ? pindexPrev->GetBlockHash() : uint256();
    if (!fluxnodeConsensus.IsBlockProducer(producerSig.fluxnodeOutpoint, nHeight, prevBlockHash, block.nTime)) {
        return state.DoS(100, error("CheckFluxnodeBlock(): invalid block producer"),
                         REJECT_INVALID, "bad-producer");
    }
    
    // Verify producer signature
    if (!fluxnodeConsensus.VerifyBlockSignature(block, producerSig)) {
        return state.DoS(100, error("CheckFluxnodeBlock(): invalid producer signature"),
                         REJECT_INVALID, "bad-producer-sig");
    }
    
    // Check quorum certificate if present
    if (!block.vchQuorumCert.empty()) {
        CDataStream ssQuorum(block.vchQuorumCert, SER_NETWORK, PROTOCOL_VERSION);
        CQuorumCertificate quorumCert;
        
        try {
            ssQuorum >> quorumCert;
        } catch (const std::exception& e) {
            return state.DoS(50, error("CheckFluxnodeBlock(): failed to deserialize quorum certificate"),
                             REJECT_INVALID, "bad-quorum-format");
        }
        
        // Validate quorum certificate
        if (!quorumCert.Validate(block.GetHash())) {
            return state.DoS(50, error("CheckFluxnodeBlock(): invalid quorum certificate"),
                             REJECT_INVALID, "bad-quorum");
        }
        
        // Check if BLS is active
        bool fBLSActive = IsBLSActive(nHeight, chainparams.GetConsensus());
        
        if (fBLSActive && quorumCert.nCertificateType == SIG_TYPE_BLS) {
            // Verify BLS aggregate signature
            if (!VerifyBLSQuorumCertificate(quorumCert, block.GetHash())) {
                return state.DoS(50, error("CheckFluxnodeBlock(): invalid BLS quorum certificate"),
                                 REJECT_INVALID, "bad-bls-quorum");
            }
        } else {
            // Verify all individual ECDSA signatures in quorum
            for (const auto& sig : quorumCert.signatures) {
                if (!fluxnodeConsensus.VerifyBlockSignature(block, sig)) {
                    return state.DoS(50, error("CheckFluxnodeBlock(): invalid signature in quorum"),
                                     REJECT_INVALID, "bad-quorum-sig");
                }
            }
        }
    }
    
    return true;
}

// Process fluxnode block signatures
bool ProcessFluxnodeBlockSignature(
    const uint256& blockHash,
    const CFluxnodeBlockSignature& signature,
    CValidationState& state)
{
    // Add signature to pending quorum
    if (!fluxnodeConsensus.AddBlockSignature(blockHash, signature)) {
        return state.Invalid(error("ProcessFluxnodeBlockSignature(): failed to add signature"),
                             REJECT_INVALID, "bad-sig");
    }
    
    // Check if we now have quorum
    if (fluxnodeConsensus.HasQuorum(blockHash)) {
        // Finalize the block
        if (!fluxnodeConsensus.FinalizeBlock(blockHash)) {
            return state.Invalid(error("ProcessFluxnodeBlockSignature(): failed to finalize block"),
                                 REJECT_INVALID, "bad-finalize");
        }
        
        LogPrintf("Block %s achieved quorum and finalized\n", blockHash.ToString());
    }
    
    return true;
}

// Validate block under fluxnode consensus rules
bool ContextualCheckFluxnodeBlock(
    const CBlock& block,
    CValidationState& state,
    const CChainParams& chainparams,
    CBlockIndex* pindexPrev)
{
    int nHeight = pindexPrev ? pindexPrev->nHeight + 1 : 0;
    
    // Skip if fluxnode consensus not active
    if (!IsFluxnodeQuorumConsensusEnabled(nHeight)) {
        return true;
    }
    
    // Check that fluxnode consensus is ready
    if (!fluxnodeConsensus.IsActive()) {
        // Allow block but warn
        LogPrintf("Warning: Fluxnode consensus not active, allowing block at height %d\n", nHeight);
        return true;
    }
    
    // Verify proper block timing
    int64_t currentTime = GetAdjustedTime();
    if (!fluxnodeConsensus.IsInProductionPhase(currentTime, nHeight) &&
        !fluxnodeConsensus.IsInValidationPhase(currentTime, nHeight) &&
        !fluxnodeConsensus.IsInFinalityPhase(currentTime, nHeight)) {
        
        return state.Invalid(error("ContextualCheckFluxnodeBlock(): block outside valid time window"),
                             REJECT_INVALID, "bad-timing");
    }
    
    // Additional contextual checks can be added here
    
    return true;
}

// Verify BLS aggregate signature in quorum certificate
bool VerifyBLSQuorumCertificate(const CQuorumCertificate& quorumCert, const uint256& blockHash)
{
    // Validate that we have a BLS certificate
    if (quorumCert.nCertificateType != SIG_TYPE_BLS) {
        LogPrintf("VerifyBLSQuorumCertificate: not a BLS certificate\n");
        return false;
    }
    
    // Check that we have an aggregate signature
    if (quorumCert.vchAggregateSignature.empty()) {
        LogPrintf("VerifyBLSQuorumCertificate: empty aggregate signature\n");
        return false;
    }
    
    // Check that we have signers
    if (quorumCert.signerOutpoints.empty()) {
        LogPrintf("VerifyBLSQuorumCertificate: no signers in certificate\n");
        return false;
    }
    
    // Collect BLS public keys from the signers
    std::vector<CBLSPublicKey> publicKeys;
    publicKeys.reserve(quorumCert.signerOutpoints.size());
    
    for (const auto& outpoint : quorumCert.signerOutpoints) {
        // Get fluxnode from cache
        if (g_fluxnodeCache.mapConfirmedFluxnodeData.count(outpoint)) {
            auto fluxnode = g_fluxnodeCache.GetFluxnodeData(outpoint);

            // Check if fluxnode has BLS key
            if (g_fluxnodeCache.mapConfirmedFluxnodeData.at(outpoint).vchBLSPubKey.size() == BLS_PUBLIC_KEY_SIZE) {
                CBLSPublicKey blsPubKey;
                blsPubKey.vchPubKey = g_fluxnodeCache.mapConfirmedFluxnodeData.at(outpoint).vchBLSPubKey;
                publicKeys.push_back(blsPubKey);
            } else {
                LogPrintf("VerifyBLSQuorumCertificate: fluxnode %s has no valid BLS key\n",
                          outpoint.ToString());
                return false;
            }
        } else {
            // TODO FLUXNODE - What about blocks that were signed long time ago, and nodes are not online anymore.
            // we could bypass checks on certs on blocks that are more than 6 hours old then current time?
            // what if a node goes down within 50 blocks, can we use the snapshot data to get bls sigs? we should be able to right?
            LogPrintf("VerifyBLSQuorumCertificate: fluxnode %s not found in cache\n",
                      outpoint.ToString());
            return false;
        }
    }
    
    // Deserialize aggregate signature
    CBLSAggregateSignature aggregateSig;
    aggregateSig.vchAggSig = quorumCert.vchAggregateSignature;
    
    // Verify the aggregate signature
    if (!BLS::VerifyAggregate(blockHash, publicKeys, aggregateSig)) {
        LogPrintf("VerifyBLSQuorumCertificate: aggregate signature verification failed\n");
        return false;
    }
    
    LogPrint("fluxnode", "VerifyBLSQuorumCertificate: successfully verified BLS quorum with %d signers\n",
             publicKeys.size());
    
    return true;
}

// Compare two chain tips for fluxnode consensus
int CompareFluxnodeChainTips(const CBlockIndex* pindex1, const CBlockIndex* pindex2)
{
    // Use fluxnode consensus fork resolution
    return fluxnodeConsensus.CompareForks(pindex1, pindex2);
}