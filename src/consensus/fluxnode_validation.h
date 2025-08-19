// Copyright (c) 2024 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef FLUX_FLUXNODE_VALIDATION_H
#define FLUX_FLUXNODE_VALIDATION_H

#include "validation.h"
#include "../primitives/block.h"
#include "../chainparams.h"
#include "../uint256.h"

class CBlockIndex;
class CValidationState;
class CFluxnodeBlockSignature;

// Process fluxnode block signatures
bool ProcessFluxnodeBlockSignature(
    const uint256& blockHash,
    const CFluxnodeBlockSignature& signature,
    CValidationState& state);

// Validation functions for fluxnode consensus
bool CheckFluxnodeBlockHeader(
    const CBlockHeader& block,
    CValidationState& state,
    const CChainParams& chainparams,
    int nHeight);

bool CheckFluxnodeBlock(
    const CBlock& block,
    CValidationState& state,
    const CChainParams& chainparams,
    CBlockIndex* pindexPrev);

bool ContextualCheckFluxnodeBlock(
    const CBlock& block,
    CValidationState& state,
    const CChainParams& chainparams,
    CBlockIndex* pindexPrev);

int CompareFluxnodeChainTips(const CBlockIndex* pindex1, const CBlockIndex* pindex2);

#endif // FLUX_FLUXNODE_VALIDATION_H