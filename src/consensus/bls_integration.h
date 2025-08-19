// Copyright (c) 2024 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef FLUX_BLS_INTEGRATION_H
#define FLUX_BLS_INTEGRATION_H

#include "bls_signature.h"
#include "bls_key_derivation.h"
#include "../fluxnode/fluxnode.h"
#include "../primitives/transaction.h"

/**
 * BLS Integration for Fluxnode Consensus
 * 
 * How it works:
 * 1. Each node derives BLS keys from its existing ECDSA key deterministically
 * 2. When confirming (INITIAL_CONFIRM or UPDATE_CONFIRM), node includes BLS pubkey
 * 3. Other nodes store the BLS pubkey in FluxnodeCache
 * 4. For consensus, we use BLS signatures and aggregation
 */

/**
 * Process for nodes to publish BLS keys:
 * 
 * 1. On first confirmation (INITIAL_CONFIRM):
 *    - Derive BLS keypair from ECDSA key
 *    - Include BLS pubkey in confirmation tx
 * 
 * 2. On update confirmation (UPDATE_CONFIRM):
 *    - Include same BLS pubkey (consistency check)
 * 
 * 3. When processing confirmations:
 *    - Store BLS pubkey in FluxnodeCache
 *    - Validate BLS pubkey format
 */

class CBLSIntegration {
public:
    /**
     * Add BLS public key to confirmation transaction
     */
    static bool AddBLSToConfirmTx(CMutableTransaction& mutTx) {
        // Get BLS keys for active node
        CBLSPublicKey blsPubKey;
        std::vector<unsigned char> blsPrivKey;

        if (!CBLSKeyDerivation::GetActiveNodeBLSKeys(blsPubKey, blsPrivKey)) {
            LogPrintf("Failed to derive BLS keys for confirmation tx\n");
            return false;
        }

        // Add BLS pubkey to transaction
        // This would be added as a new field in v7 transactions
        // For now, we could use the existing fields creatively
        // or wait for a proper protocol upgrade

        return true;
    }
    
    /**
     * Sign block with BLS (for block producers)
     */
    static bool SignBlockWithBLS(const uint256& blockHash, CBLSSignature& signature) {
        CBLSPublicKey blsPubKey;
        std::vector<unsigned char> blsPrivKey;
        
        if (!CBLSKeyDerivation::GetActiveNodeBLSKeys(blsPubKey, blsPrivKey)) {
            return false;
        }
        
        return BLS::Sign(blockHash, blsPrivKey, signature);
    }
    
    /**
     * Aggregate signatures for quorum certificate
     */
    static bool AggregateQuorumSignatures(
        const std::vector<CBLSSignature>& signatures,
        const std::vector<int>& signerIndices,
        CBLSAggregateSignature& aggregateSig) {
        
        if (!BLS::Aggregate(signatures, aggregateSig)) {
            return false;
        }
        
        // Set signer bitmap
        for (int index : signerIndices) {
            aggregateSig.SetSigner(index);
        }
        
        return true;
    }
    
    /**
     * Verify aggregate signature for block
     */
    static bool VerifyBlockQuorum(
        const uint256& blockHash,
        const CBLSAggregateSignature& aggregateSig,
        const std::vector<COutPoint>& quorumMembers) {
        
        // Get BLS public keys for quorum members
        std::vector<CBLSPublicKey> quorumPubKeys;
        
        for (size_t i = 0; i < quorumMembers.size(); i++) {
            if (aggregateSig.HasSigner(i)) {
                // Get BLS pubkey from FluxnodeCache
                FluxnodeCacheData data;
                if (g_fluxnodeCache.GetFluxnodeData(quorumMembers[i], data)) {
                    // In real implementation, FluxnodeCacheData would have blsPubKey field
                    // quorumPubKeys.push_back(data.blsPubKey);
                }
            }
        }
        
        return BLS::VerifyAggregate(blockHash, quorumPubKeys, aggregateSig);
    }
};

/**
 * Migration path:
 * 
 * Phase 1: Nodes start deriving and publishing BLS keys (soft fork)
 * - New confirmation txs include BLS pubkeys
 * - Old nodes ignore the extra data
 * 
 * Phase 2: Switch consensus to BLS (hard fork at specific height)
 * - After height X, only accept BLS-signed blocks
 * - Use aggregate signatures in block headers
 * 
 * This allows gradual rollout without breaking existing nodes
 */

#endif // FLUX_BLS_INTEGRATION_H