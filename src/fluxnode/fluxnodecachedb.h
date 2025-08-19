// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

//
// Created by ja on 11/14/19.
//

#ifndef ZELCASH_FLUXNODECACHEDB_H
#define ZELCASH_FLUXNODECACHEDB_H

#include "dbwrapper.h"
#include "uint256.h"
#include "serialize.h"
#include "utiltime.h"
#include <boost/filesystem/path.hpp>
#include <map>
#include <vector>
#include <algorithm>

class FluxnodeCacheData;
class FluxnodeSnapshot;
class COutPoint;
class CFluxnodeTxBlockUndo;

class CDeterministicFluxnodeDB : public CDBWrapper
{
public:
    CDeterministicFluxnodeDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

private:
    CDeterministicFluxnodeDB(const CDeterministicFluxnodeDB&);
    void operator=(const CDeterministicFluxnodeDB&);

public:
    bool WriteFluxnodeCacheData(const FluxnodeCacheData& data);
    bool ReadFluxnodeCacheData(const COutPoint& outpoint, FluxnodeCacheData& data);
    bool EraseFluxnodeCacheData(const COutPoint& outpoint);
    bool FluxnodeCacheDataExists(const COutPoint& outpoint);

    bool LoadFluxnodeCacheData();

    bool WriteBlockUndoFluxnodeData(const uint256& p_blockHash, CFluxnodeTxBlockUndo& p_undoData);
    bool ReadBlockUndoFluxnodeData(const uint256 &p_blockHash, CFluxnodeTxBlockUndo& p_undoData);

    bool CleanupOldFluxnodeData();
    
    // Snapshot functions for deterministic consensus
    bool WriteFluxnodeSnapshot(const FluxnodeSnapshot& snapshot);
    bool ReadFluxnodeSnapshot(int nHeight, FluxnodeSnapshot& snapshot);
    bool EraseFluxnodeSnapshot(int nHeight);
    std::vector<int> GetSnapshotHeights();
    bool CleanupOldSnapshots(int nCurrentHeight);

};

#endif //ZELCASH_FLUXNODECACHEDB_H
