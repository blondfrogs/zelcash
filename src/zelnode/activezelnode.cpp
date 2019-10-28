// Copyright (c) 2014-2016 The Dash developers
// Copyright (c) 2015-2019 The PIVX developers
// Copyright (c) 2019 The Zel developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activezelnode.h"
#include "addrman.h"
#include "zelnode/zelnode.h"
#include "zelnode/zelnodeconfig.h"
#include "zelnode/zelnodeman.h"
#include "protocol.h"
#include "zelnode/spork.h"
#include "key_io.h"
#include "zelnode/benchmarks.h"

#include "evo/deterministicmns.h"





// Keep track of the active Masternode
CActiveMasternodeInfo activeMasternodeInfo;
CActiveMasternodeManager* activeMasternodeManager;

std::string CActiveMasternodeManager::GetStateString() const
{
    switch (state) {
        case MASTERNODE_WAITING_FOR_PROTX:
            return "WAITING_FOR_PROTX";
        case MASTERNODE_POSE_BANNED:
            return "POSE_BANNED";
        case MASTERNODE_REMOVED:
            return "REMOVED";
        case MASTERNODE_OPERATOR_KEY_CHANGED:
            return "OPERATOR_KEY_CHANGED";
        case MASTERNODE_READY:
            return "READY";
        case MASTERNODE_ERROR:
            return "ERROR";
        default:
            return "UNKNOWN";
    }
}

std::string CActiveMasternodeManager::GetStatus() const
{
    switch (state) {
        case MASTERNODE_WAITING_FOR_PROTX:
            return "Waiting for ProTx to appear on-chain";
        case MASTERNODE_POSE_BANNED:
            return "Masternode was PoSe banned";
        case MASTERNODE_REMOVED:
            return "Masternode removed from list";
        case MASTERNODE_OPERATOR_KEY_CHANGED:
            return "Operator key changed or revoked";
        case MASTERNODE_READY:
            return "Ready";
        case MASTERNODE_ERROR:
            return "Error. " + strError;
        default:
            return "Unknown";
    }
}

void CActiveMasternodeManager::Init()
{
    LOCK(cs_main);

    if (!fZelnode) return;

    if (!deterministicMNManager->IsDIP3Enforced()) return;

    // Check that our local network configuration is correct
    if (!fListen) {
        // listen option is probably overwritten by smth else, no good
        state = MASTERNODE_ERROR;
        strError = "Masternode must accept connections from outside. Make sure listen configuration option is not overwritten by some another parameter.";
        LogPrintf("CActiveDeterministicMasternodeManager::Init -- ERROR: %s\n", strError);
        return;
    }

    if (!GetLocalAddress(activeMasternodeInfo.service)) {
        state = MASTERNODE_ERROR;
        return;
    }

    CDeterministicMNList mnList = deterministicMNManager->GetListAtChainTip();

    CDeterministicMNCPtr dmn = mnList.GetMNByOperatorKey(*activeMasternodeInfo.blsPubKeyOperator);
    if (!dmn) {
        // MN not appeared on the chain yet
        return;
    }

    if (!mnList.IsMNValid(dmn->proTxHash)) {
        if (mnList.IsMNPoSeBanned(dmn->proTxHash)) {
            state = MASTERNODE_POSE_BANNED;
        } else {
            state = MASTERNODE_REMOVED;
        }
        return;
    }

    mnListEntry = dmn;

    LogPrintf("CActiveMasternodeManager::Init -- proTxHash=%s, proTx=%s\n", mnListEntry->proTxHash.ToString(), mnListEntry->ToString());

    if (activeMasternodeInfo.service != mnListEntry->pdmnState->addr) {
        state = MASTERNODE_ERROR;
        strError = "Local address does not match the address from ProTx";
        LogPrintf("CActiveMasternodeManager::Init -- ERROR: %s", strError);
        return;
    }

    if (Params().NetworkIDString() != "regtest") {
        // Check socket connectivity
        LogPrintf("CActiveDeterministicMasternodeManager::Init -- Checking inbound connection to '%s'\n", activeMasternodeInfo.service.ToString());
        SOCKET hSocket;
        bool fConnected = ConnectSocket(activeMasternodeInfo.service, hSocket, nConnectTimeout) && IsSelectableSocket(hSocket);
        CloseSocket(hSocket);

        if (!fConnected) {
            state = MASTERNODE_ERROR;
            strError = "Could not connect to " + activeMasternodeInfo.service.ToString();
            LogPrintf("CActiveDeterministicMasternodeManager::Init -- ERROR: %s\n", strError);
            return;
        }
    }

    activeMasternodeInfo.proTxHash = mnListEntry->proTxHash;
    activeMasternodeInfo.outpoint = mnListEntry->collateralOutpoint;
    state = MASTERNODE_READY;
}

void CActiveMasternodeManager::UpdatedBlockTip(const CBlockIndex* pindexNew, const CBlockIndex* pindexFork, bool fInitialDownload)
{
    LOCK(cs_main);

    if (!fZelnode) return;

    if (!deterministicMNManager->IsDIP3Enforced(pindexNew->nHeight)) return;

    if (state == MASTERNODE_READY) {
        auto mnList = deterministicMNManager->GetListForBlock(pindexNew);
        if (!mnList.IsMNValid(mnListEntry->proTxHash)) {
            // MN disappeared from MN list
            state = MASTERNODE_REMOVED;
            activeMasternodeInfo.proTxHash = uint256();
            activeMasternodeInfo.outpoint.SetNull();
            // MN might have reappeared in same block with a new ProTx
            Init();
        } else if (mnList.GetMN(mnListEntry->proTxHash)->pdmnState->pubKeyOperator != mnListEntry->pdmnState->pubKeyOperator) {
            // MN operator key changed or revoked
            state = MASTERNODE_OPERATOR_KEY_CHANGED;
            activeMasternodeInfo.proTxHash = uint256();
            activeMasternodeInfo.outpoint.SetNull();
            // MN might have reappeared in same block with a new ProTx
            Init();
        }
    } else {
        // MN might have (re)appeared with a new ProTx or we've found some peers and figured out our local address
        Init();
    }
}

bool CActiveMasternodeManager::GetLocalAddress(CService& addrRet)
{
    // First try to find whatever local address is specified by externalip option
    bool fFoundLocal = GetLocal(addrRet) && IsValidNetAddr(addrRet);
    if (!fFoundLocal && Params().NetworkIDString() == "regtest") {
        if (Lookup("127.0.0.1", addrRet, GetListenPort(), false)) {
            fFoundLocal = true;
        }
    }
    if (!fFoundLocal) {
        bool empty = true;


        LOCK(cs_vNodes);
        BOOST_FOREACH(CNode* pnode, vNodes)
        {
            empty = false;
            if (pnode->addr.IsIPv4())
                fFoundLocal = GetLocal(activeMasternodeInfo.service, &pnode->addr) && IsValidNetAddr(activeMasternodeInfo.service);
            if (fFoundLocal)
                break;
        }

        // nothing and no live connections, can't do anything for now
        if (empty) {
            strError = "Can't detect valid external address. Please consider using the externalip configuration option if problem persists. Make sure to use IPv4 address only.";
            LogPrintf("CActiveMasternodeManager::GetLocalAddress -- ERROR: %s\n", strError);
            return false;
        }
    }
    return true;
}

bool CActiveMasternodeManager::IsValidNetAddr(CService addrIn)
{
    // TODO: regtest is fine with any addresses for now,
    // should probably be a bit smarter if one day we start to implement tests for this
    return Params().NetworkIDString() == "regtest" ||
           (addrIn.IsIPv4() && IsReachable(addrIn) && addrIn.IsRoutable());
}





















//
// Bootup the Zelnode, look for a 10000 ZEL input and register on the network
//
void ActiveZelnode::ManageStatus()
{
    std::string errorMessage;

    if (!fZelnode) return;

    if (fBenchmarkFailed) {
        notCapableReason = strprintf("Benchmarking tests failed, please restart the node to try again");
        LogPrintf("%s - %s\n", __func__, notCapableReason);
        return;
    }

    if (!fBenchmarkComplete) {
        notCapableReason = strprintf("Benchmarking isn't complete yet, please try again in a minute");
        LogPrintf("%s - %s\n", __func__, notCapableReason);
        return;
    }

    if (fDebug) LogPrintf("%s - Begin\n", __func__);

    //need correct blocks to send ping
    if (Params().NetworkID() != CBaseChainParams::REGTEST && !zelnodeSync.IsBlockchainSynced()) {
        status = ACTIVE_ZELNODE_SYNC_IN_PROCESS;
        LogPrintf("%s - %s\n", __func__, GetStatus());
        return;
    }

    if (status == ACTIVE_ZELNODE_SYNC_IN_PROCESS) status = ACTIVE_ZELNODE_INITIAL;

    if (status == ACTIVE_ZELNODE_INITIAL) {
        Zelnode* pzn;
        pzn = zelnodeman.Find(pubKeyZelnode);
        if (pzn != NULL) {
            if (!CheckBenchmarks(pzn->tier)) {
                status = ACTIVE_ZELNODE_NOT_CAPABLE;
                notCapableReason = strprintf("Failed benchmarks test for %s", pzn->Tier());
                LogPrintf("%s - %s\n", __func__, notCapableReason);
                return;
            }
            pzn->Check();
            if (pzn->IsEnabled() && pzn->protocolVersion == PROTOCOL_VERSION) EnableHotColdZelnode(pzn->vin, pzn->addr);
        }
    }

    if (status != ACTIVE_ZELNODE_STARTED) {
        // Set defaults
        status = ACTIVE_ZELNODE_NOT_CAPABLE;
        notCapableReason = "";

        if (pwalletMain->IsLocked()) {
            notCapableReason = "Wallet is locked.";
            LogPrintf("%s - not capable: %s\n", __func__, notCapableReason);
            return;
        }

        if (pwalletMain->GetBalance() == 0) {
            notCapableReason = "Hot node, waiting for remote activation.";
            LogPrintf("%s - not capable: %s\n", __func__, notCapableReason);
            return;
        }

        if (strZelnodeAddr.empty()) {
            if (!GetLocal(service)) {
                notCapableReason = "Can't detect external address. Please use the zelnodeaddr configuration option.";
                LogPrintf("%s - not capable: %s\n", __func__, notCapableReason);
                return;
            }
        } else {
            service = CService(strZelnodeAddr);
        }

        // The service needs the correct default port to work properly
        if(!ZelnodeBroadcast::CheckDefaultPort(strZelnodeAddr, errorMessage, "ActiveZelnode::ManageStatus()"))
            return;

        LogPrintf("%s - Checking inbound connection to '%s'\n", __func__, service.ToString());

        CNode* pnode = ConnectNode((CAddress)service, NULL, false);
        if (!pnode) {
            notCapableReason = "Could not connect to " + service.ToString();
            LogPrintf("%s - not capable: %s\n", __func__, notCapableReason);
            return;
        }
        pnode->Release();

        // Choose coins to use
        CPubKey pubKeyCollateralAddress;
        CKey keyCollateralAddress;

        if (GetZelNodeVin(vin, pubKeyCollateralAddress, keyCollateralAddress)) {
            if (GetInputAge(vin) < Params().GetConsensus().nMasternodeMinimumConfirmations) {
                status = ACTIVE_ZELNODE_INPUT_TOO_NEW;
                notCapableReason = strprintf("%s - %d confirmations", GetStatus(), GetInputAge(vin));
                LogPrintf("%s - %s\n", __func__, notCapableReason);
                return;
            }

            LOCK(pwalletMain->cs_wallet);
            pwalletMain->LockCoin(vin.prevout);

            // send to all nodes
            CPubKey pubKeyZelnode;
            CKey keyZelnode;

            if (!obfuScationSigner.SetKey(strZelnodePrivKey, errorMessage, keyZelnode, pubKeyZelnode)) {
                notCapableReason = "Error upon calling SetKey: " + errorMessage;
                LogPrintf("Register::ManageStatus() - %s\n", notCapableReason);
                return;
            }

            ZelnodeBroadcast znb;
            if (!CreateBroadcast(vin, service, keyCollateralAddress, pubKeyCollateralAddress, keyZelnode, pubKeyZelnode, errorMessage, znb)) {
                notCapableReason = "Error on Register: " + errorMessage;
                LogPrintf("%s - %s\n", __func__, notCapableReason);
                return;
            }

            //send to all peers
            LogPrintf("%s - Relay broadcast vin = %s\n", __func__, vin.ToString());
            znb.Relay();

            LogPrintf("%s - Is capable zelnode!\n", __func__);
            status = ACTIVE_ZELNODE_STARTED;

            return;
        } else {
            notCapableReason = "Could not find suitable coins!";
            LogPrintf("%s - %s\n", __func__, notCapableReason);
            return;
        }
    }

    //send to all peers
    if (!SendZelnodePing(errorMessage)) {
        LogPrintf("%s - Error on Ping: %s\n", __func__, errorMessage);
    }
}

std::string ActiveZelnode::GetStatus()
{
    switch (status) {
        case ACTIVE_ZELNODE_INITIAL:
            return "Node just started, not yet activated";
        case ACTIVE_ZELNODE_SYNC_IN_PROCESS:
            return "Sync in progress. Must wait until sync is complete to start Zelnode";
        case ACTIVE_ZELNODE_INPUT_TOO_NEW:
            return strprintf("Zelnode input must have at least %d confirmations", Params().GetConsensus().nMasternodeMinimumConfirmations);
        case ACTIVE_ZELNODE_NOT_CAPABLE:
            return "Not capable zelnode: " + notCapableReason;
        case ACTIVE_ZELNODE_STARTED:
            return "Zelnode successfully started";
        default:
            return "unknown";
    }
}

bool ActiveZelnode::SendZelnodePing(std::string& errorMessage)
{
    if (status != ACTIVE_ZELNODE_STARTED) {
        errorMessage = "Zelnode is not in a running status";
        return false;
    }

    CPubKey pubKeyZelnode;
    CKey keyZelnode;

    if (!obfuScationSigner.SetKey(strZelnodePrivKey, errorMessage, keyZelnode, pubKeyZelnode)) {
        errorMessage = strprintf("Error upon calling SetKey: %s\n", errorMessage);
        return false;
    }

    LogPrintf("%s - Relay Zelnode Ping vin = %s\n", __func__, vin.ToString());

    ZelnodePing znp(vin);
    if (!znp.Sign(keyZelnode, pubKeyZelnode)) {
        errorMessage = "Couldn't sign Zelnode Ping";
        return false;
    }

    // Update lastPing for our zelnode in Zelnode list
    Zelnode* pzn = zelnodeman.Find(vin);
    if (pzn != NULL) {
        if (pzn->IsPingedWithin(ZELNODE_PING_SECONDS, znp.sigTime)) {
            errorMessage = "Too early to send Zelnode Ping";
            return false;
        }

        pzn->lastPing = znp;
        zelnodeman.mapSeenZelnodePing.insert(make_pair(znp.GetHash(), znp));

        //zelnodeman.mapSeenZelnodeBroadcast.lastPing is probably outdated, so we'll update it
        ZelnodeBroadcast znb(*pzn);
        uint256 hash = znb.GetHash();
        if (zelnodeman.mapSeenZelnodeBroadcast.count(hash)) zelnodeman.mapSeenZelnodeBroadcast[hash].lastPing = znp;

        znp.Relay();

        return true;
    } else {
        // Seems like we are trying to send a ping while the Zelnode is not registered in the network
        errorMessage = "Obfuscation Zelnode List doesn't include our Zelnode, shutting down Zelnode pinging service! " + vin.ToString();
        status = ACTIVE_ZELNODE_NOT_CAPABLE;
        notCapableReason = errorMessage;
        return false;
    }
}

bool ActiveZelnode::CreateBroadcast(std::string strService, std::string strKeyZelnode, std::string strTxHash, std::string strOutputIndex, std::string& errorMessage, ZelnodeBroadcast &znb, bool fOffline)
{
    CTxIn vin;
    CPubKey pubKeyCollateralAddress;
    CKey keyCollateralAddress;
    CPubKey pubKeyZelnode;
    CKey keyZelnode;

    //need correct blocks to send ping
    if (!fOffline && !zelnodeSync.IsBlockchainSynced()) {
        errorMessage = "Sync in progress. Must wait until sync is complete to start Zelnode";
        LogPrintf("%s - %s\n", __func__, errorMessage);
        return false;
    }

    if (!obfuScationSigner.SetKey(strKeyZelnode, errorMessage, keyZelnode, pubKeyZelnode)) {
        errorMessage = strprintf("Can't find keys for zelnode %s - %s", strService, errorMessage);
        LogPrintf("%s - %s\n", __func__, errorMessage);
        return false;
    }

    if (!GetZelNodeVin(vin, pubKeyCollateralAddress, keyCollateralAddress, strTxHash, strOutputIndex)) {
        errorMessage = strprintf("Could not allocate vin %s:%s for zelnode %s", strTxHash, strOutputIndex,
                                 strService);
        LogPrintf("%s - %s\n", __func__, errorMessage);
        return false;
    }

    CService service = CService(strService);

    // The service needs the correct default port to work properly
    if (!ZelnodeBroadcast::CheckDefaultPort(strService, errorMessage, "ActiveZelnode::CreateBroadcast()"))
        return false;

    addrman.Add(CAddress(service), CNetAddr("127.0.0.1"), 2 * 60 * 60);

    return CreateBroadcast(vin, CService(strService), keyCollateralAddress, pubKeyCollateralAddress, keyZelnode,
                           pubKeyZelnode, errorMessage, znb);
}

bool ActiveZelnode::CreateBroadcast(CTxIn vin, CService service, CKey key, CPubKey pubKey, CKey keyZelnode,
                                    CPubKey pubKeyZelnode, std::string& errorMessage, ZelnodeBroadcast& znb)
{
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) return false;

    ZelnodePing znp(vin);
    if (!znp.Sign(keyZelnode, pubKeyZelnode)) {
        errorMessage = strprintf("Failed to sign ping, vin: %s", vin.ToString());
        LogPrintf("%s -  %s\n", __func__, errorMessage);
        znb = ZelnodeBroadcast();
        return false;
    }

    znb = ZelnodeBroadcast(service, vin, pubKey, pubKeyZelnode, PROTOCOL_VERSION);
    znb.lastPing = znp;
    if (!znb.Sign(key)) {
        errorMessage = strprintf("Failed to sign broadcast, vin: %s", vin.ToString());
        LogPrintf("%s -  %s\n", __func__, errorMessage);
        znb = ZelnodeBroadcast();
        return false;
    }

    return true;
}

bool ActiveZelnode::GetZelNodeVin(CTxIn& vin, CPubKey& pubkey, CKey& secretKey)
{
    return GetZelNodeVin(vin, pubkey, secretKey, "", "");
}

bool ActiveZelnode::GetZelNodeVin(CTxIn& vin, CPubKey& pubkey, CKey& secretKey, std::string strTxHash, std::string strOutputIndex)
{
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) return false;

    // Find possible candidates
    TRY_LOCK(pwalletMain->cs_wallet, fWallet);
    if (!fWallet) return false;

    vector<std::pair<COutput, CAmount>> possibleCoins = SelectCoinsZelnode();
    COutput* selectedOutput;

    // Find the vin
    if (!strTxHash.empty()) {
        // Let's find it
        uint256 txHash = uint256S(strTxHash);
        int outputIndex;
        try {
            outputIndex = std::stoi(strOutputIndex.c_str());
        } catch (const std::exception& e) {
            LogPrintf("%s: %s on strOutputIndex\n", __func__, e.what());
            return false;
        }

        bool found = false;
        for (auto& pair : possibleCoins) {
            if (pair.first.tx->GetHash() == txHash && pair.first.i == outputIndex) {
                selectedOutput = &pair.first;
                found = true;
                break;
            }
        }
        if (!found) {
            LogPrintf("%s - Could not locate valid vin\n", __func__);
            return false;
        }
    } else {
        // No output specified,  Select the first one
        if (possibleCoins.size() > 0) {
            selectedOutput = &possibleCoins[0].first;
        } else {
            LogPrintf("%s - Could not locate specified vin from possible list\n", __func__);
            return false;
        }
    }

    // At this point we have a selected output, retrieve the associated info
    return GetVinFromOutput(*selectedOutput, vin, pubkey, secretKey);
}

// Extract Zelnode vin information from output
bool ActiveZelnode::GetVinFromOutput(COutput out, CTxIn& vin, CPubKey& pubkey, CKey& secretKey)
{
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) return false;

    CScript pubScript;

    vin = CTxIn(out.tx->GetHash(), out.i);
    pubScript = out.tx->vout[out.i].scriptPubKey; // the inputs PubKey

    CTxDestination address1;
    ExtractDestination(pubScript, address1);

    CKeyID* keyid;
    keyid = boost::get<CKeyID>(&address1);

    if (!keyid) {
        LogPrintf("%s - Address does not refer to a key\n", __func__);
        return false;
    }

    if (!pwalletMain->GetKey(*keyid, secretKey)) {
        LogPrintf("%s - Private key for address is not known\n", __func__);
        return false;
    }

    pubkey = secretKey.GetPubKey();
    return true;
}

// get all possible outputs for running Zelnode
vector<std::pair<COutput, CAmount>> ActiveZelnode::SelectCoinsZelnode()
{
    vector<COutput> vCoins;
    vector<std::pair<COutput, CAmount>> filteredCoins;
    vector<COutPoint> confLockedCoins;

    // Temporary unlock ZN coins from zelnode.conf
    if (GetBoolArg("-znconflock", true)) {
        uint256 znTxHash;
        for (ZelnodeConfig::ZelnodeEntry zelnodeEntry : zelnodeConfig.getEntries()) {
            znTxHash.SetHex(zelnodeEntry.getTxHash());

            int nIndex;
            if(!zelnodeEntry.castOutputIndex(nIndex))
                continue;

            COutPoint outpoint = COutPoint(znTxHash, nIndex);
            confLockedCoins.push_back(outpoint);
            pwalletMain->UnlockCoin(outpoint);
        }
    }

    // Retrieve all possible outputs
    pwalletMain->AvailableCoins(vCoins);

    // Lock ZN coins from zelnode.conf back if they where temporary unlocked
    if (!confLockedCoins.empty()) {
        for (COutPoint outpoint: confLockedCoins)
            pwalletMain->LockCoin(outpoint);
    }

    // Filter
    for (const COutput& out : vCoins) {
        if (out.tx->vout[out.i].nValue == ZELNODE_BASIC_COLLATERAL * COIN) { //exactly
            filteredCoins.push_back(std::make_pair(out, ZELNODE_BASIC_COLLATERAL * COIN));
        }

        else if (out.tx->vout[out.i].nValue == ZELNODE_SUPER_COLLATERAL * COIN) { //exactly
            filteredCoins.push_back(std::make_pair(out, ZELNODE_SUPER_COLLATERAL * COIN));
        }

        else if (out.tx->vout[out.i].nValue == ZELNODE_BAMF_COLLATERAL * COIN) { //exactly
            filteredCoins.push_back(std::make_pair(out, ZELNODE_BAMF_COLLATERAL * COIN));
        }
    }
    return filteredCoins;
}

// when starting a Zelnode, this can enable to run as a hot wallet with no funds
bool ActiveZelnode::EnableHotColdZelnode(CTxIn& newVin, CService& newService)
{
    if (!fZelnode) return false;

    status = ACTIVE_ZELNODE_STARTED;

    //The values below are needed for signing znping messages going forward
    vin = newVin;
    service = newService;

    LogPrintf("%s - Enabled! You may shut down the cold daemon.\n", __func__);

    return true;
}