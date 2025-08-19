// Copyright (c) 2024 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "fluxnode_messages.h"
#include "fluxnode_consensus.h"
#include "fluxnode_validation.h"
#include "../main.h"
#include "../net.h"
#include "../protocol.h"
#include "../hash.h"
#include "../util.h"
#include "../timedata.h"
#include "../key_io.h"
#include "../chain.h"
#include "../fluxnode/activefluxnode.h"

// Global fluxnode consensus instance
extern CFluxnodeConsensus fluxnodeConsensus;

// CFluxnodeBlockProposal implementation
bool CFluxnodeBlockProposal::Sign(const CKey& key) {
    CHashWriter hasher(SER_GETHASH, 0);
    hasher << block.GetHash();
    hasher << producerOutpoint;
    hasher << nTimeProposed;
    
    uint256 hash = hasher.GetHash();
    std::vector<unsigned char> vchSig;
    
    if (!key.Sign(hash, vchSig)) {
        return false;
    }
    
    vchProducerSig = vchSig;
    return true;
}


bool CFluxnodeBlockProposal::Verify(const CPubKey& pubKey) const {
    CHashWriter hasher(SER_GETHASH, 0);
    hasher << block.GetHash();
    hasher << producerOutpoint;
    hasher << nTimeProposed;
    
    uint256 hash = hasher.GetHash();
    return pubKey.Verify(hash, vchProducerSig);
}


// Message processing functions
bool ProcessFluxnodeBlockProposal(CNode* pfrom, const CFluxnodeBlockProposal& proposal, CValidationState& state) {
    LOCK(cs_main);
    
    uint256 blockHash = proposal.block.GetHash();
    int nHeight = chainActive.Height() + 1;
    
    LogPrint("fluxnode", "Received block proposal %s from peer %d\n",
             blockHash.ToString(), pfrom->id);
    
    // Verify the block producer is valid for this height and time
    uint256 prevBlockHash = chainActive.Tip() ? chainActive.Tip()->GetBlockHash() : uint256();
    int64_t nBlockTime = proposal.block.GetBlockTime();
    
    if (!fluxnodeConsensus.IsBlockProducer(proposal.producerOutpoint, nHeight, prevBlockHash, nBlockTime)) {
        // Check which producer slot this should be
        int producerIndex = fluxnodeConsensus.GetProducerIndex(proposal.producerOutpoint, nHeight, prevBlockHash);
        if (producerIndex >= 0) {
            // This node is a valid producer but wrong time slot
            return state.Invalid(error("ProcessFluxnodeBlockProposal: Producer %s in wrong time slot (index %d)",
                                     proposal.producerOutpoint.ToString(), producerIndex),
                                REJECT_INVALID, "bad-producer-timing");
        } else {
            // This node is not a producer at all for this height
            return state.DoS(20, error("ProcessFluxnodeBlockProposal: Invalid block producer %s",
                                      proposal.producerOutpoint.ToString()),
                            REJECT_INVALID, "bad-producer");
        }
    }
    
    // LOCAL decision: Should we relay this block based on reputation?
    // This doesn't affect consensus validity, just our relay behavior
    if (!fluxnodeConsensus.ShouldRelayBlockFrom(proposal.producerOutpoint)) {
        LogPrint("fluxnode", "Not relaying block from low reputation producer %s\n",
                 proposal.producerOutpoint.ToString());
        // Note: We still process it locally, just don't relay
    }
    
    // Verify timing
    int64_t currentTime = GetAdjustedTime();
    if (!fluxnodeConsensus.IsInProductionPhase(currentTime, nHeight)) {
        return state.Invalid(error("ProcessFluxnodeBlockProposal: Block proposed outside production phase"),
                             REJECT_INVALID, "bad-timing");
    }
    
    // Store the proposal as pending (NOT accepted yet)
    fluxnodeConsensus.AddPendingProposal(proposal);
    
    // Validate the block proposal (but don't accept it yet)
    CBlock block = proposal.block;
    
    // Basic validation without accepting the block
    auto verifier = libflux::ProofVerifier::Disabled();
    if (!CheckBlock(block, state, Params(), verifier, false, false)) {
        return state.Invalid(error("ProcessFluxnodeBlockProposal: CheckBlock failed"),
                            REJECT_INVALID, "bad-block");
    }
    
    // Check if block builds on current tip
    if (block.hashPrevBlock != chainActive.Tip()->GetBlockHash()) {
        return state.Invalid(error("ProcessFluxnodeBlockProposal: Block doesn't connect to tip"),
                            REJECT_INVALID, "bad-prevblk");
    }
    
    // Block is valid but NOT accepted yet - waiting for quorum certificate
    LogPrint("fluxnode", "Stored pending block proposal %s, waiting for quorum signatures\n",
             blockHash.ToString());
    
    // If we're in the validation quorum, sign the block
    if (true) {  // Changed condition for signing
        // If we're in the validation quorum, sign the block
        if (activeFluxnode.deterministicOutPoint.IsNull()) {
            // Not running as an active fluxnode
            return true;
        }
        
        if (fluxnodeConsensus.IsInValidationQuorum(activeFluxnode.deterministicOutPoint, nHeight, blockHash)) {
            // We're in the validation quorum - sign the block
            if (fluxnodeConsensus.SignValidationAsActiveNode(blockHash)) {
                LogPrint("fluxnode", "Successfully signed block %s as validator\n", blockHash.ToString());
                
                // Get our signature from the pending quorum (it was just added)
                CQuorumCertificate cert = fluxnodeConsensus.GetQuorumCertificate(blockHash);
                if (!cert.signatures.empty()) {
                    // Get the last signature (ours)
                    const CFluxnodeBlockSignature& ourSig = cert.signatures.back();
                    
                    // Convert to message format
                    CFluxnodeBlockSigMessage sigMsg;
                    sigMsg.blockHash = blockHash;
                    sigMsg.nHeight = nHeight;
                    sigMsg.fluxnodeOutpoint = ourSig.fluxnodeOutpoint;
                    sigMsg.nTier = ourSig.nTier;
                    sigMsg.vchSig = ourSig.vchSig;
                    sigMsg.sigTime = ourSig.sigTime;
                    sigMsg.nSigType = ourSig.nSigType;
                    
                    // Broadcast our signature to the network
                    BroadcastFluxnodeBlockSignature(blockHash, sigMsg);
                }
            } else {
                LogPrintf("Warning: Failed to sign block %s as validator\n", blockHash.ToString());
            }
        }
        
        // Relay the proposal
        RelayFluxnodeBlockProposal(proposal);
    }
    
    return true;
}

bool ProcessFluxnodeBlockSig(CNode* pfrom, const CFluxnodeBlockSigMessage& sigMsg, CValidationState& state) {
    LOCK(cs_main);
    
    LogPrint("fluxnode", "Received block signature for %s from peer %d\n",
             sigMsg.blockHash.ToString(), pfrom->id);
    
    // Verify the signer is in the validation quorum
    if (!fluxnodeConsensus.IsInValidationQuorum(sigMsg.fluxnodeOutpoint,
                                                   sigMsg.nHeight, 
                                                   sigMsg.blockHash)) {
        return state.DoS(10, error("ProcessFluxnodeBlockSig: Signer not in validation quorum"),
                         REJECT_INVALID, "bad-validator");
    }
    
    // Convert message data back to CFluxnodeBlockSignature for processing
    CFluxnodeBlockSignature signature;
    signature.fluxnodeOutpoint = sigMsg.fluxnodeOutpoint;
    signature.nTier = sigMsg.nTier;
    signature.vchSig = sigMsg.vchSig;
    signature.sigTime = sigMsg.sigTime;
    signature.nSigType = sigMsg.nSigType;
    
    // Process the signature
    if (!ProcessFluxnodeBlockSignature(sigMsg.blockHash, signature, state)) {
        return false;
    }
    
    // Check if we have quorum
    if (fluxnodeConsensus.HasQuorum(sigMsg.blockHash)) {
        // Get the quorum certificate
        CQuorumCertificate cert = fluxnodeConsensus.GetQuorumCertificate(sigMsg.blockHash);
        
        // Get the pending block proposal
        CFluxnodeBlockProposal proposal = fluxnodeConsensus.GetPendingProposal(sigMsg.blockHash);
        if (proposal.block.IsNull()) {
            LogPrintf("Error: Have quorum for block %s but no pending proposal\n", sigMsg.blockHash.ToString());
            return true;
        }
        
        // Embed the certificate in the block
        CBlock finalBlock = proposal.block;
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << cert;
        finalBlock.vchQuorumCert = std::vector<unsigned char>(ss.begin(), ss.end());
        
        // Now process the finalized block with embedded certificate
        CValidationState blockState;
        if (ProcessNewBlock(blockState, Params(), pfrom, &finalBlock, true, NULL)) {
            LogPrintf("Successfully accepted finalized block %s with quorum certificate\n", 
                     sigMsg.blockHash.ToString());
            
            // Mark as finalized in our tracking
            fluxnodeConsensus.FinalizeBlock(sigMsg.blockHash);
            
            // Remove from pending
            fluxnodeConsensus.RemovePendingProposal(sigMsg.blockHash);
        } else {
            LogPrintf("Failed to process finalized block %s: %s\n", 
                     sigMsg.blockHash.ToString(), blockState.GetRejectReason());
        }
    }
    
    // Relay the signature
    RelayFluxnodeBlockSignature(sigMsg);
    
    return true;
}

bool ProcessFluxnodeQuorumCert(CNode* pfrom, const CFluxnodeQuorumCertMessage& certMsg, CValidationState& state) {
    LOCK(cs_main);
    
    LogPrint("fluxnode", "Received quorum certificate for %s from peer %d\n",
             certMsg.blockHash.ToString(), pfrom->id);
    
    // Reconstruct the CQuorumCertificate from the message
    CQuorumCertificate certificate;
    certificate.blockHash = certMsg.blockHash;
    certificate.nHeight = certMsg.nHeight;
    certificate.nCertificateType = certMsg.nCertificateType;
    certificate.nTimeCreated = certMsg.nTimeCreated;
    
    if (certMsg.nCertificateType == 1) { // BLS
        certificate.vchAggregateSignature = certMsg.vchAggregateSignature;
        certificate.nSignersBitmap = certMsg.nSignersBitmap;
        certificate.signerOutpoints = certMsg.signerOutpoints;
    } else { // ECDSA
        // Convert message signatures back to CFluxnodeBlockSignature
        for (const auto& msgSig : certMsg.signatures) {
            CFluxnodeBlockSignature sig;
            sig.fluxnodeOutpoint = msgSig.fluxnodeOutpoint;
            sig.nTier = msgSig.nTier;
            sig.vchSig = msgSig.vchSig;
            sig.sigTime = msgSig.sigTime;
            sig.nSigType = msgSig.nSigType;
            certificate.signatures.push_back(sig);
        }
    }
    
    // Validate the certificate
    if (!certificate.HasQuorum()) {
        return state.Invalid(error("ProcessFluxnodeQuorumCert: Certificate doesn't have quorum"),
                             REJECT_INVALID, "bad-cert-quorum");
    }
    
    // Store and finalize
    uint256 blockHash = certificate.blockHash;
    
    // Add all signatures from the certificate
    for (const auto& sig : certificate.signatures) {
        fluxnodeConsensus.AddBlockSignature(blockHash, sig);
    }
    
    // Finalize the block
    if (!fluxnodeConsensus.IsBlockFinalized(blockHash)) {
        fluxnodeConsensus.FinalizeBlock(blockHash);
        
        // Update block index
        BlockMap::iterator mi = mapBlockIndex.find(blockHash);
        if (mi != mapBlockIndex.end() && mi->second) {
            CBlockIndex* pindex = mi->second;
            
            // Store certificate in block
            CBlock block;
            if (ReadBlockFromDisk(block, pindex, Params().GetConsensus())) {
                CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                ss << certificate;
                block.vchQuorumCert = std::vector<unsigned char>(ss.begin(), ss.end());
                
                // Write updated block back to disk
                CDiskBlockPos blockPos(pindex->nFile, pindex->nDataPos);
                if (!WriteBlockToDisk(block, blockPos, Params().MessageStart())) {
                    LogPrintf("Failed to write quorum certificate to block %s\n", blockHash.ToString());
                }
            }
        }
    }
    
    // Relay the certificate
    RelayQuorumCertificate(certMsg);
    
    return true;
}


// Message broadcasting functions
void BroadcastFluxnodeBlockProposal(const CFluxnodeBlockProposal& proposal) {
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << proposal;
    
    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes) {
        if (!pnode->fRelayTxes) continue;
        pnode->PushMessage(MNBLOCKPROPOSAL, proposal);
    }
}

void BroadcastFluxnodeBlockSignature(const uint256& blockHash, const CFluxnodeBlockSigMessage& sigMsg) {
    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes) {
        if (!pnode->fRelayTxes) continue;
        pnode->PushMessage(MNBLOCKSIG, sigMsg);
    }
}

void BroadcastQuorumCertificate(const CFluxnodeQuorumCertMessage& certMsg) {
    
    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes) {
        if (!pnode->fRelayTxes) continue;
        pnode->PushMessage(MNQUORUMCERT, certMsg);
    }
}



// Relay functions
void RelayFluxnodeBlockProposal(const CFluxnodeBlockProposal& proposal) {
    CInv inv(MSG_FLUXNODE_BLOCK_PROPOSAL, proposal.GetHash());
    
    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes) {
        if (!pnode->fRelayTxes) continue;
        pnode->PushInventory(inv);
    }
}

void RelayFluxnodeBlockSignature(const CFluxnodeBlockSigMessage& sigMsg) {
    // Use hash of signature message as inventory
    CHashWriter hasher(SER_GETHASH, 0);
    hasher << sigMsg;
    uint256 hash = hasher.GetHash();
    
    CInv inv(MSG_FLUXNODE_BLOCK_SIG, hash);
    
    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes) {
        if (!pnode->fRelayTxes) continue;
        if (pnode->setInventoryKnown.count(inv)) continue;
        pnode->PushInventory(inv);
    }
}

void RelayQuorumCertificate(const CFluxnodeQuorumCertMessage& certMsg) {
    // Use hash of the certificate message as inventory
    CHashWriter hasher(SER_GETHASH, 0);
    hasher << certMsg;
    uint256 hash = hasher.GetHash();
    
    CInv inv(MSG_FLUXNODE_QUORUM_CERT, hash);
    
    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes) {
        if (!pnode->fRelayTxes) continue;
        pnode->PushInventory(inv);
    }
}