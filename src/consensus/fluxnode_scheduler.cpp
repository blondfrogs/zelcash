// Copyright (c) 2024 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "fluxnode_scheduler.h"
#include "fluxnode_consensus.h"
#include "fluxnode_messages.h"
#include "validation.h"
#include "../main.h"
#include "../net.h"
#include "../util.h"
#include "../utiltime.h"
#include "../init.h"
#include "../miner.h"
#include "../timedata.h"

#include <boost/thread.hpp>
#include <memory>

static boost::thread_group* fluxnodeSchedulerThreads = NULL;
static volatile bool fStopFluxnodeScheduler = false;

// Main scheduler loop
void FluxnodeSchedulerThread(const CChainParams& chainparams) {
    LogPrintf("Fluxnode scheduler thread started\n");
    
    RenameThread("flux-mnscheduler");
    
    // Cache for tracking last processed height
    int nLastProcessedHeight = 0;
    
    try {
        while (!fStopFluxnodeScheduler) {
            // Sleep for 100ms
            MilliSleep(100);
            
            if (ShutdownRequested()) {
                break;
            }
            
            // Skip if not synced
            if (IsInitialBlockDownload(chainparams)) {
                continue;
            }
            
            // Skip if fluxnode consensus not enabled
            int nCurrentHeight = chainActive.Height();
            if (!IsFluxnodeQuorumConsensusEnabled(nCurrentHeight)) {
                continue;
            }
            
            // Initialize consensus if needed
            if (!fluxnodeConsensus.IsActive()) {
                if (!fluxnodeConsensus.Initialize(nCurrentHeight)) {
                    LogPrintf("Failed to initialize fluxnode consensus at height %d\n", nCurrentHeight);
                    MilliSleep(5000);
                    continue;
                }
            }
            
            // Get current time and calculate block slot
            int64_t nCurrentTime = GetAdjustedTime();
            int nNextHeight = nCurrentHeight + 1;
            
            // Calculate expected time for next block
            int64_t nExpectedBlockTime = nNextHeight * FLUXNODE_BLOCK_INTERVAL;
            int64_t nTimeUntilNextBlock = nExpectedBlockTime - nCurrentTime;
            
            // Check if we're a block producer for the next height
            uint256 prevBlockHash = chainActive.Tip() ? chainActive.Tip()->GetBlockHash() : uint256();
            std::vector<COutPoint> vProducers = fluxnodeConsensus.GetBlockProducers(nNextHeight, prevBlockHash);
            
            bool fIsProducer = false;
            int nOurProducerIndex = -1;
            for (size_t i = 0; i < vProducers.size(); i++) {
                if (vProducers[i] == fluxnodeOutPoint && !fluxnodeOutPoint.IsNull()) {
                    fIsProducer = true;
                    nOurProducerIndex = i;
                    break;
                }
            }
            
            // Check if it's our time to produce
            if (fIsProducer && nNextHeight > nLastProcessedHeight) {
                // Calculate our time slot
                int64_t nSlotStart = nExpectedBlockTime + (nOurProducerIndex * FLUXNODE_PRODUCER_SLOT_TIME);
                int64_t nSlotEnd = nSlotStart + FLUXNODE_PRODUCER_SLOT_TIME;
                
                // Check if we're in our time window
                if (nCurrentTime >= nSlotStart && nCurrentTime < nSlotEnd) {
                    // Check if block already exists at this height
                    if (chainActive.Height() < nNextHeight) {
                        if (nOurProducerIndex == 0) {
                            LogPrintf("Our turn as PRIMARY producer for block at height %d\n", nNextHeight);
                        } else {
                            LogPrintf("Our turn as BACKUP producer %d for block at height %d (primary may be offline)\n", 
                                    nOurProducerIndex, nNextHeight);
                        }
                        
                        // Create new block
                        if (!CreateFluxnodeBlock(chainparams, nNextHeight)) {
                            LogPrintf("Failed to create fluxnode block at height %d\n", nNextHeight);
                        }
                        
                        nLastProcessedHeight = nNextHeight;
                    }
                }
            }
            
            // Validation phase: 10-20 seconds
            else if (fluxnodeConsensus.IsInValidationPhase(nCurrentTime, nNextHeight)) {
                // Check if we're in the validation quorum
                if (fluxnodeConsensus.IsInValidationQuorum(fluxnodeOutPoint, nNextHeight, prevBlockHash)) {
                    // Process any pending blocks that need our signature
                    ProcessPendingBlockSignatures(nNextHeight);
                }
            }
            
            // Finality phase: 20-30 seconds
            else if (fluxnodeConsensus.IsInFinalityPhase(nCurrentTime, nNextHeight)) {
                // Check for blocks that achieved quorum
                CheckAndFinalizeBlocks(nNextHeight);
                
                // Update schedule for next round
                if (nNextHeight > nLastProcessedHeight) {
                    fluxnodeConsensus.UpdateBlockProducerCache(nNextHeight + 1, prevBlockHash);
                }
            }

            
            // Clean up old pending signatures
            CleanupOldPendingData(nCurrentHeight);
        }
    }
    catch (const boost::thread_interrupted&) {
        LogPrintf("Fluxnode scheduler thread interrupted\n");
        throw;
    }
    catch (const std::exception& e) {
        LogPrintf("Fluxnode scheduler thread exception: %s\n", e.what());
    }
    
    LogPrintf("Fluxnode scheduler thread stopped\n");
}

// Create a new block as fluxnode
bool CreateFluxnodeBlock(const CChainParams& chainparams, int nHeight) {
    LOCK(cs_main);
    
    // Create block template
    std::unique_ptr<CBlockTemplate> pblocktemplate(CreateNewBlock(chainparams, CScript()));
    if (!pblocktemplate.get()) {
        LogPrintf("CreateFluxnodeBlock: Failed to create block template\n");
        return false;
    }
    
    CBlock* pblock = &pblocktemplate->block;
    
    // Set block version for fluxnode consensus
    pblock->nVersion = 5;
    
    // Remove POW fields (nonce, solution)
    pblock->nNonce = uint256();
    pblock->nSolution.clear();
    
    // Set proper block time
    pblock->nTime = GetAdjustedTime();
    
    // Sign the block as producer
    CFluxnodeBlockSignature producerSig;
    producerSig.fluxnodeOutpoint = fluxnodeOutPoint;
    producerSig.nTier = GetFluxnodeTierFromOutpoint(fluxnodeOutPoint);
    producerSig.sigTime = pblock->nTime;
    
    // Would need actual fluxnode key to sign
    // producerSig.Sign(pblock->GetHash(), fluxnodeKey);
    
    // Serialize and add to block
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << producerSig;
    pblock->vchProducerSig = std::vector<unsigned char>(ss.begin(), ss.end());
    
    // Create block proposal
    CFluxnodeBlockProposal proposal;
    proposal.block = *pblock;
    proposal.producerOutpoint = fluxnodeOutPoint;
    proposal.vchProducerSig = producerSig.vchSig;
    proposal.nTimeProposed = pblock->nTime;
    
    // Process our own block
    CValidationState state;
    bool fProcessingBlockSuccessful = ProcessNewBlock(state, chainparams, nullptr, pblock, true, NULL);
    
    if (fProcessingBlockSuccessful) {
        LogPrintf("Successfully created fluxnode block %s at height %d\n",
                 pblock->GetHash().ToString(), nHeight);
        
        // Broadcast the proposal
        BroadcastFluxnodeBlockProposal(proposal);
        return true;
    } else {
        LogPrintf("Failed to process fluxnode block: %s\n", state.GetRejectReason());
        return false;
    }
}

// Process blocks that need our signature
void ProcessPendingBlockSignatures(int nHeight) {
    LOCK(cs_main);
    
    // Check recent blocks for signature requests
    for (int h = std::max(0, nHeight - 5); h <= nHeight; h++) {
        if (h >= chainActive.Height()) continue;
        
        CBlockIndex* pindex = chainActive[h];
        if (!pindex) continue;
        
        uint256 blockHash = pindex->GetBlockHash();
        
        // Check if we should sign this block
        if (fluxnodeConsensus.IsInValidationQuorum(fluxnodeOutPoint, h, blockHash)) {
            // Check if we already signed
            CQuorumCertificate cert = fluxnodeConsensus.GetQuorumCertificate(blockHash);
            bool alreadySigned = false;
            
            for (const auto& sig : cert.signatures) {
                if (sig.fluxnodeOutpoint == fluxnodeOutPoint) {
                    alreadySigned = true;
                    break;
                }
            }
            
            if (!alreadySigned) {
                // Create and broadcast our signature
                CFluxnodeBlockSignature signature;
                signature.fluxnodeOutpoint = fluxnodeOutPoint;
                signature.nTier = GetFluxnodeTierFromOutpoint(fluxnodeOutPoint);
                signature.sigTime = GetAdjustedTime();
                
                // Would need actual fluxnode key to sign
                // signature.Sign(blockHash, fluxnodeKey);
                
                // Add to local consensus
                fluxnodeConsensus.AddBlockSignature(blockHash, signature);
                
                // Convert to message format for broadcast
                CFluxnodeBlockSigMessage sigMsg;
                sigMsg.blockHash = blockHash;
                sigMsg.nHeight = h;
                sigMsg.fluxnodeOutpoint = signature.fluxnodeOutpoint;
                sigMsg.nTier = signature.nTier;
                sigMsg.vchSig = signature.vchSig;
                sigMsg.sigTime = signature.sigTime;
                sigMsg.nSigType = signature.nSigType;
                
                // Broadcast signature
                BroadcastFluxnodeBlockSignature(blockHash, sigMsg);
                
                LogPrintf("Signed block %s at height %d as validator\n", 
                         blockHash.ToString(), h);
            }
        }
    }
}

// Check and finalize blocks that achieved quorum
void CheckAndFinalizeBlocks(int nHeight) {
    LOCK(cs_main);
    
    // Check recent blocks for finalization
    for (int h = std::max(0, nHeight - 10); h <= nHeight; h++) {
        if (h >= chainActive.Height()) continue;
        
        CBlockIndex* pindex = chainActive[h];
        if (!pindex) continue;
        
        uint256 blockHash = pindex->GetBlockHash();
        
        // Check if block has quorum but isn't finalized
        if (fluxnodeConsensus.HasQuorum(blockHash) &&
            !fluxnodeConsensus.IsBlockFinalized(blockHash)) {
            
            // Finalize the block
            if (fluxnodeConsensus.FinalizeBlock(blockHash)) {
                LogPrintf("Finalized block %s at height %d\n", 
                         blockHash.ToString(), h);
                
                // Get and broadcast the quorum certificate
                CQuorumCertificate cert = fluxnodeConsensus.GetQuorumCertificate(blockHash);
                
                // Convert to message format
                CFluxnodeQuorumCertMessage certMsg;
                certMsg.blockHash = cert.blockHash;
                certMsg.nHeight = cert.nHeight;
                certMsg.nCertificateType = cert.nCertificateType;
                certMsg.nTimeCreated = cert.nTimeCreated;
                
                if (cert.nCertificateType == 1) { // BLS
                    certMsg.vchAggregateSignature = cert.vchAggregateSignature;
                    certMsg.nSignersBitmap = cert.nSignersBitmap;
                    certMsg.signerOutpoints = cert.signerOutpoints;
                } else { // ECDSA
                    // Convert signatures to message format
                    for (const auto& sig : cert.signatures) {
                        CFluxnodeBlockSigMessage sigMsg;
                        sigMsg.blockHash = blockHash;
                        sigMsg.nHeight = h;
                        sigMsg.fluxnodeOutpoint = sig.fluxnodeOutpoint;
                        sigMsg.nTier = sig.nTier;
                        sigMsg.vchSig = sig.vchSig;
                        sigMsg.sigTime = sig.sigTime;
                        sigMsg.nSigType = sig.nSigType;
                        certMsg.signatures.push_back(sigMsg);
                    }
                }
                
                BroadcastQuorumCertificate(certMsg);
            }
        }
    }
}

// Clean up old pending data
void CleanupOldPendingData(int nCurrentHeight) {
    // Clean up data older than 100 blocks
    // This would be implemented in the consensus class
    // For now, this is a placeholder
}

// Get fluxnode tier from outpoint
int GetFluxnodeTierFromOutpoint(const COutPoint& outpoint) {
    // Look up the tier from fluxnode cache
    // This is a simplified version
    return TIER_CUMULUS;
}

// Start the fluxnode scheduler
void StartFluxnodeScheduler(const CChainParams& chainparams) {
    if (fluxnodeSchedulerThreads != NULL) {
        return; // Already started
    }
    
    LogPrintf("Starting fluxnode scheduler\n");
    
    fStopFluxnodeScheduler = false;
    fluxnodeSchedulerThreads = new boost::thread_group();
    
    // Start scheduler thread
    fluxnodeSchedulerThreads->create_thread(
        boost::bind(&FluxnodeSchedulerThread, boost::cref(chainparams))
    );
}

// Stop the fluxnode scheduler
void StopFluxnodeScheduler() {
    if (fluxnodeSchedulerThreads == NULL) {
        return;
    }
    
    LogPrintf("Stopping fluxnode scheduler\n");
    
    fStopFluxnodeScheduler = true;
    
    if (fluxnodeSchedulerThreads != NULL) {
        fluxnodeSchedulerThreads->interrupt_all();
        fluxnodeSchedulerThreads->join_all();
        delete fluxnodeSchedulerThreads;
        fluxnodeSchedulerThreads = NULL;
    }
}