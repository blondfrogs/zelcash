// Copyright (c) 2024 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef FLUX_FLUXNODE_SCHEDULER_H
#define FLUX_FLUXNODE_SCHEDULER_H

#include "../chainparams.h"
#include "../primitives/block.h"

// Fluxnode scheduler functions
void StartFluxnodeScheduler(const CChainParams& chainparams);
void StopFluxnodeScheduler();

// Block production functions
bool CreateFluxnodeBlock(const CChainParams& chainparams, int nHeight);
void ProcessPendingBlockSignatures(int nHeight);
void CheckAndFinalizeBlocks(int nHeight);
void CleanupOldPendingData(int nCurrentHeight);

// Helper functions
int GetFluxnodeTierFromOutpoint(const COutPoint& outpoint);

// Main scheduler thread
void FluxnodeSchedulerThread(const CChainParams& chainparams);

#endif // FLUX_FLUXNODE_SCHEDULER_H