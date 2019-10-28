// Copyright (c) 2018 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "clientversion.h"
#include "consensus/validation.h"
#include "hash.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "wallet/wallet.h"

#include "cbtx.h"
#include "deterministicmns.h"
#include "specialtx.h"

bool CheckSpecialTx(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    if (tx.nVersion < DZN_TX_VERSION || tx.nType == TRANSACTION_NORMAL)
        return true;

    if (pindexPrev && pindexPrev->nHeight + 1 <  Params().GetConsensus().vUpgrades[Consensus::UPGRADE_DIP0003].nActivationHeight) {
        return state.DoS(10, false, REJECT_INVALID, "bad-tx-type");
    }

    switch (tx.nType) {
    case TRANSACTION_PROVIDER_REGISTER:
        return CheckProRegTx(tx, pindexPrev, state);
    case TRANSACTION_PROVIDER_UPDATE_SERVICE:
        return CheckProUpServTx(tx, pindexPrev, state);
    case TRANSACTION_PROVIDER_UPDATE_REGISTRAR:
        return CheckProUpRegTx(tx, pindexPrev, state);
    case TRANSACTION_PROVIDER_UPDATE_REVOKE:
        return CheckProUpRevTx(tx, pindexPrev, state);
    case TRANSACTION_COINBASE:
        return CheckCbTx(tx, pindexPrev, state);
    }

    return state.DoS(10, false, REJECT_INVALID, "bad-tx-type-check");
}

bool ProcessSpecialTx(const CTransaction& tx, const CBlockIndex* pindex, CValidationState& state)
{
    if (tx.nVersion != 3 || tx.nType == TRANSACTION_NORMAL) {
        return true;
    }

    switch (tx.nType) {
    case TRANSACTION_PROVIDER_REGISTER:
    case TRANSACTION_PROVIDER_UPDATE_SERVICE:
    case TRANSACTION_PROVIDER_UPDATE_REGISTRAR:
    case TRANSACTION_PROVIDER_UPDATE_REVOKE:
        return true; // handled in batches per block
    case TRANSACTION_COINBASE:
        return true; // nothing to do
    }

    return state.DoS(100, false, REJECT_INVALID, "bad-tx-type-proc");
}

bool UndoSpecialTx(const CTransaction& tx, const CBlockIndex* pindex)
{
    if (tx.nVersion != 3 || tx.nType == TRANSACTION_NORMAL) {
        return true;
    }

    switch (tx.nType) {
    case TRANSACTION_PROVIDER_REGISTER:
    case TRANSACTION_PROVIDER_UPDATE_SERVICE:
    case TRANSACTION_PROVIDER_UPDATE_REGISTRAR:
    case TRANSACTION_PROVIDER_UPDATE_REVOKE:
        return true; // handled in batches per block
    case TRANSACTION_COINBASE:
        return true; // nothing to do
    }

    return false;
}

bool ProcessSpecialTxsInBlock(const CBlock& block, const CBlockIndex* pindex, CValidationState& state, bool fJustCheck, bool fCheckCbTxMerleRoots)
{
    static int64_t nTimeLoop = 0;
    static int64_t nTimeQuorum = 0;
    static int64_t nTimeDMN = 0;
    static int64_t nTimeMerkle = 0;

    int64_t nTime1 = GetTimeMicros();

    for (int i = 0; i < (int)block.vtx.size(); i++) {
        const CTransaction& tx = block.vtx[i];
        if (!CheckSpecialTx(tx, pindex->pprev, state)) {
            return false;
        }
        if (!ProcessSpecialTx(tx, pindex, state)) {
            return false;
        }
    }

    int64_t nTime2 = GetTimeMicros(); nTimeLoop += nTime2 - nTime1;
    LogPrint("bench", "        - Loop: %.2fms [%.2fs]\n", 0.001 * (nTime2 - nTime1), nTimeLoop * 0.000001);

    if (!deterministicMNManager->ProcessBlock(block, pindex, state, fJustCheck)) {
        return false;
    }

    int64_t nTime3 = GetTimeMicros(); nTimeDMN += nTime3 - nTime2;
    LogPrint("bench", "        - deterministicMNManager: %.2fms [%.2fs]\n", 0.001 * (nTime3 - nTime2), nTimeDMN * 0.000001);

    if (fCheckCbTxMerleRoots && !CheckCbTxMerkleRoots(block, pindex, state)) {
        return false;
    }

    int64_t nTime4 = GetTimeMicros(); nTimeMerkle += nTime4 - nTime3;
    LogPrint("bench", "        - CheckCbTxMerkleRoots: %.2fms [%.2fs]\n", 0.001 * (nTime4 - nTime3), nTimeMerkle * 0.000001);

    return true;
}

bool UndoSpecialTxsInBlock(const CBlock& block, const CBlockIndex* pindex)
{
    for (int i = (int)block.vtx.size() - 1; i >= 0; --i) {
        const CTransaction& tx = block.vtx[i];
        if (!UndoSpecialTx(tx, pindex)) {
            return false;
        }
    }

    if (!deterministicMNManager->UndoBlock(block, pindex)) {
        return false;
    }

    return true;
}

uint256 CalcTxInputsHash(const CTransaction& tx)
{
    CHashWriter hw(CLIENT_VERSION, SER_GETHASH);
    for (const auto& in : tx.vin) {
        hw << in.prevout;
    }
    return hw.GetHash();
}
