// Copyright (c) 2019 The Zelcash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util.h>
#include <utiltime.h>
#include "benchmarks.h"
#include <regex>
#include "zelnode/zelnode.h"

#define SYSTEM_BENCH_MIN_MAJOR_VERSION 0
#define SYSTEM_BENCH_MIN_MINOR_VERSION 4
#define SYSTEM_BENCH_MIN_PATCH_VERSION 12


bool fBenchmarkComplete = false;
bool fBenchmarkFailed = false;
bool fBenchmarkRestart = false;
Benchmarks benchmarks;

std::regex re_cpu("CPU cores:[^0-9]*([0-9]+)\\n");
std::regex re_ram("RAM:[^0-9]*([0-9.]+)G\\n");
std::regex re_ssd("([0-9.]+)(G|T|M)\\s*(SSD|HDD)\\n");
std::regex re_iops(".*?([0-9.]+).?(k?).?iops,");
std::regex re_dd("average:.* ([0-9.]+)");
std::regex re_version("sysbench ([0-9.]+)");
std::regex re_eps("events per second:[^0-9.]+([0-9.]+)\\n");

std::regex re_eps_time("total time:[^0-9.]+([0-9.]+)s\\n");
std::regex re_eps_events("total number of events:[^0-9.]+([0-9.]+)\\n");

std::string sysbenchversion = "sysbench --version";
// This downloads the script, we have the current script as a string in benchmarks.h
// The same script is in the contrib/devtools/nench.sh for testing
//std::string nenchtest = "wget -qO- wget.racing/nench.sh | sudo bash";
std::string sysbenchinstall_1 = "sudo apt -y install sysbench";
std::string sysbenchinstall_2 = "sudo apt install sysbench";
std::string sysbenchfetch = "curl -s https://packagecloud.io/install/repositories/akopytov/sysbench/script.deb.sh | sudo bash";

bool Benchmarks::IsNenchCheckComplete()
{
    return nNumberOfCores && (nSSD || nHDD) && nAmountofRam && nIOPS && nDDWrite;
}

bool Benchmarks::IsSysBenchCheckComplete()
{
    return nEventsPerSecond;
}

std::string Benchmarks::GetSysbenchVersion()
{
    return strprintf("%d.%d.%d", benchmarks.nMajorVersion, benchmarks.nMinorVersion, benchmarks.nPatchVersion);
}

std::string Benchmarks::NenchResultToString()
{
    return "Current nench Stats: \n"
           "CPU Cores : " + std::to_string(benchmarks.nNumberOfCores) + "\n"
         + "RAM : " + std::to_string(benchmarks.nAmountofRam) + " G\n"
         + "SSD : " + std::to_string(benchmarks.nSSD) + " G\n"
         + "HDD : " + std::to_string(benchmarks.nHDD) + " G\n"
         + "IOPS : " + std::to_string(benchmarks.nIOPS) + "\n"
         + "DD_WRITE : " + std::to_string(benchmarks.nDDWrite) + " MiB/s\n";
}

std::string Benchmarks::ToString()
{
    return "CPU Cores : " + std::to_string(benchmarks.nNumberOfCores) + "\n"
         + "RAM : " + std::to_string(benchmarks.nAmountofRam) + " G\n"
         + "SSD : " + std::to_string(benchmarks.nSSD) + " G\n"
         + "HDD : " + std::to_string(benchmarks.nHDD) + " G\n"
         + "IOPS : " + std::to_string(benchmarks.nIOPS) + "\n"
         + "DD_WRITE : " + std::to_string(benchmarks.nDDWrite) + " MiB/s\n"
         + "EPS : " + std::to_string(benchmarks.nEventsPerSecond) + " events / sec\n";
}

void ThreadBenchmarkZelnode()
{
    // Make this thread recognisable as the wallet flushing thread
    RenameThread("zelcash-zelnode-benchmarking");
    LogPrintf("Starting Zelnodes Benchmarking Thread\n");

    while(true) {
        if (fBenchmarkFailed || fBenchmarkComplete || fBenchmarkRestart) {
            boost::this_thread::interruption_point();
            MilliSleep(5000);

            if (fBenchmarkRestart) {
                LogPrintf("---Restarting benchmarks\n");
                fBenchmarkRestart = false;
                fBenchmarkComplete = false;
                fBenchmarkFailed = false;
                benchmarks.SetNull();
            } else if (benchmarks.nTime > 0 && (GetTime() - 60 * 30) > benchmarks.nTime) {
                fBenchmarkRestart = true;
                continue;
            } else {
                continue;
            }
        }

        boost::this_thread::interruption_point();
        // Check the sysbench version
        CheckSysBenchVersion();

        if (!benchmarks.fVersionValid) {
            fBenchmarkFailed = true;
            benchmarks.strFailedReason = "Failed to find a valid sysbench version";
            LogPrintf("---%s\n", benchmarks.strFailedReason);
            continue;
        }

        boost::this_thread::interruption_point();
        /** Run the nench System Test */
        if (fBenchmarkRestart)
            continue;

        boost::this_thread::interruption_point();
        RunNenchTest();

        if (fBenchmarkRestart)
            continue;

        /** Check the nench Results */
        if (!benchmarks.IsNenchCheckComplete()) {
            fBenchmarkFailed = true;
            benchmarks.strFailedReason = "Failed to get nench stats";
            LogPrintf("---%s - Current stats: %s\n", benchmarks.strFailedReason, benchmarks.NenchResultToString());
            continue;
        }

        /** Run the sysbench System Test */
        if (fBenchmarkRestart)
            continue;

        RunSysBenchTest();

        if (fBenchmarkRestart)
            continue;

        /** Check the sysbench Results */
        if (!benchmarks.IsSysBenchCheckComplete()) {
            fBenchmarkFailed = true;
            benchmarks.strFailedReason = "Failed to get events per seconds from sysbench";
            LogPrintf("---%s\n", benchmarks.strFailedReason);
            continue;
        }
        boost::this_thread::interruption_point();
        fBenchmarkComplete = true;
        benchmarks.nTime = GetTime();
    }
}

std::string GetStdoutFromCommand(std::string cmd) {

    std::string data;
    FILE * stream;
    const int max_buffer = 250;
    char buffer[max_buffer];
    //cmd.append(" 2>&1"); // Do we want STDERR?

    stream = popen(cmd.c_str(), "r");
    if (stream) {
        while (!feof(stream))
            if (fgets(buffer, max_buffer, stream) != NULL) data.append(buffer);
        pclose(stream);
    }
    return data;
}

bool CheckSysBenchInstalled()
{
    std::string result = GetStdoutFromCommand(sysbenchversion);

    std::smatch version_match;
    // Get CPU metrics
    if (std::regex_search(result, version_match, re_version) && version_match.size() > 1) {
        return true;
    }

    return false;
}

bool CheckSysBenchVersion()
{
    std::string result = GetStdoutFromCommand(sysbenchversion);

    std::smatch version_match;
    // Get CPU metrics
    if (std::regex_search(result, version_match, re_version) && version_match.size() > 1) {
        // Split by period (1.0.16 - > [1,0,16])
        std::vector<std::string> vec = split(version_match.str(1), ".");

        if (vec.size() >= 1) benchmarks.nMajorVersion = stoi(vec[0]);
        if (vec.size() >= 2) benchmarks.nMinorVersion = stoi(vec[1]);
        if (vec.size() >= 3) benchmarks.nPatchVersion = stoi(vec[2]);

        // Check major version number
        if (vec.size() >= 1) {

            if (benchmarks.nMajorVersion < SYSTEM_BENCH_MIN_MAJOR_VERSION)
                return false;
            if (benchmarks.nMajorVersion > SYSTEM_BENCH_MIN_MAJOR_VERSION) {
                benchmarks.fVersionValid = true;
                return true;
            }
        }

        // Check minor version number
        if (vec.size() >= 2) {
            if (benchmarks.nMinorVersion < SYSTEM_BENCH_MIN_MINOR_VERSION)
                return false;
            if (benchmarks.nMinorVersion > SYSTEM_BENCH_MIN_MINOR_VERSION) {
                benchmarks.fVersionValid = true;
                return true;
            }
        }

        // Check patch version number
        if (vec.size() >= 3) {
            if (benchmarks.nPatchVersion < SYSTEM_BENCH_MIN_PATCH_VERSION)
                return false;
            if (benchmarks.nPatchVersion >= SYSTEM_BENCH_MIN_PATCH_VERSION) {
                benchmarks.fVersionValid = true;
                return true;
            }
        }

        return false;
    }

    return false;
}

void RunNenchTest()
{
    LogPrintf("---Starting nench test\n");
    std::smatch cpu_match;
    std::smatch ram_match;
    std::smatch ssd_match;
    std::smatch iops_match;
    std::smatch ddwrite_match;

    std::string result = GetStdoutFromCommand(strNenchScript + " | bash");

    // Get CPU metrics
    if (std::regex_search(result, cpu_match, re_cpu) && cpu_match.size() > 1) {
        benchmarks.nNumberOfCores = stoi(cpu_match.str(1));
        LogPrintf("---Found cores: %d\n", benchmarks.nNumberOfCores);
    }

    // Get RAM metrics
    if (std::regex_search(result, ram_match, re_ram) && ram_match.size() > 1) {
        benchmarks.nAmountofRam = stof(ram_match.str(1));
        LogPrintf("---Found ram: %d\n", benchmarks.nAmountofRam);
    }

    std::string copy = result;
    // Get SSD metrics
    while (regex_search(copy, ssd_match, re_ssd) && ssd_match.size() > 1)
    {
        // Default for Gigabyte
        float multiplier = 1;

        if (ssd_match.str(2) == "M") { // Megabytes
            multiplier = 0.0001;
        } else if (ssd_match.str(2) == "T") { // Terabyte
            multiplier = 1000;
        }

        if (ssd_match.str(3) == "SSD") {
            float num = stof(ssd_match.str(1)) * multiplier;
            benchmarks.nSSD += num;
            LogPrintf("---Found SSD: %0.6f G\n", num);
        } else if (ssd_match.str(3) == "HDD") {
            float num = stof(ssd_match.str(1)) * multiplier;
            benchmarks.nHDD += num;
            LogPrintf("---Found HDD: %0.6f G\n", num);
        }
        copy = ssd_match.suffix();
    }

    // Get IOPS metrics
    if (std::regex_search(result, iops_match, re_iops) && iops_match.size() > 1) {
        float multiplier= 1;
        if (iops_match.str(2) == "k")
            multiplier = 1000;
        float num = stof(iops_match.str(1)) * multiplier;

        benchmarks.nIOPS = num;
        LogPrintf("---Found iops: %u\n", benchmarks.nIOPS);
    }

    // Get DD_WRITE metrics
    if (std::regex_search(result, ddwrite_match, re_dd) && ddwrite_match.size() > 1) {
        benchmarks.nDDWrite = stof(ddwrite_match.str(1));
        LogPrintf("---Found DD_WRITE: %u\n", benchmarks.nDDWrite);
    }

    LogPrintf("---Finished nench test\n");
}

void SetupSysBench()
{
    /** Install and check sysbench version */
    LogPrintf("---sysbench system setup starting\n");
    // install the system package and sysbench
    if (!CheckSysBenchInstalled()) {
        InstallSysBenchPackage();
        InstallSysBench_1();
        if(!CheckSysBenchInstalled())
            InstallSysBench_2();
    } else {
        LogPrintf("---sysbench already installed\n");
    }

    // calling install should upgrade the sysbench
    if (!CheckSysBenchVersion()) {
        InstallSysBench_1();
        InstallSysBench_2();
        if (!CheckSysBenchVersion()) {
            LogPrintf("---sysbench latest version failed check: %d.%d.%d\n", benchmarks.nMajorVersion, benchmarks.nMinorVersion, benchmarks.nPatchVersion);
        }
    } else {
        LogPrintf("---sysbench found version: %d.%d.%d\n", benchmarks.nMajorVersion, benchmarks.nMinorVersion, benchmarks.nPatchVersion);
    }

    LogPrintf("---sysbench system setup completed\n");
}

void RunSysBenchTest()
{
    std::string version0_command = "sysbench --test=cpu --num-threads=" + std::to_string(benchmarks.nNumberOfCores) + " --cpu-max-prime=60000 --max-time=20 run";
    std::string version1_command = "sysbench --test=cpu --threads=" + std::to_string(benchmarks.nNumberOfCores) + " --cpu-max-prime=60000 --time=20 run";

    LogPrintf("---Starting sysbench test\n");
    std::string result = "";
    if (benchmarks.nMajorVersion > 0)
        result = GetStdoutFromCommand(version1_command);
    else
        result = GetStdoutFromCommand(version0_command);

    std::smatch eps_batch;
    std::smatch eps_time;
    std::smatch eps_events;

    if (benchmarks.nMajorVersion > 0) {
        // Get CPU metrics
        if (std::regex_search(result, eps_batch, re_eps) && eps_batch.size() > 1) {
            benchmarks.nEventsPerSecond = stof(eps_batch.str(1));
            LogPrintf("---Found eps v1: %u\n", benchmarks.nEventsPerSecond);
        }
    } else {
        // Get Time
        std::regex_search(result, eps_time, re_eps_time);

        // Get Events
        std::regex_search(result, eps_events, re_eps_events);

        if (eps_time.size() > 1 && eps_events.size() > 1) {
            benchmarks.nEventsPerSecond = stof(eps_events.str(1)) / stof(eps_time.str(1));
            LogPrintf("---Found eps v0: %u\n", benchmarks.nEventsPerSecond);
        }
    }

    LogPrintf("---Finished sysbench test\n");
}

void InstallSysBenchPackage()
{
    LogPrintf("---Fetching sysbench\n");
    std::string getpackage = GetStdoutFromCommand(sysbenchfetch);
    LogPrintf("---Finished Fetching sysbench\n");

    //LogPrintf("GetPackage : %s", getpackage);
}

void InstallSysBench_1()
{
    LogPrintf("---Installing sysbench 1\n");
    std::string installsysbench = GetStdoutFromCommand(sysbenchinstall_1);
    LogPrintf("---Finished Installing sysbench 1\n");

    //LogPrintf("InstallSysbench 1 : %s", installsysbench);
}

void InstallSysBench_2()
{
    LogPrintf("---Installing sysbench 2\n");
    std::string installsysbench = GetStdoutFromCommand(sysbenchinstall_2);
    LogPrintf("---Finished Installing sysbench 2 \n");

    //LogPrintf("InstallSysbench 2 : %s", installsysbench);
}

bool CheckBenchmarks(int& tier)
{
    if (GetBoolArg("-testnet", false)) {
        if (GetBoolArg("-testnetbypass", false)) {
            return true;
        }
    }

    if (/**benchmarks.nNumberOfCores < 8 ||*/ benchmarks.nAmountofRam >= 30 && (benchmarks.nSSD + benchmarks.nHDD) >= 600 && benchmarks.nEventsPerSecond >= 500 && benchmarks.nIOPS >= 700 && benchmarks.nDDWrite >= 200) {
        tier = Zelnode::BAMF;
        return true;
    } else if (/**benchmarks.nNumberOfCores < 4 ||*/ benchmarks.nAmountofRam >= 7 && (benchmarks.nSSD + benchmarks.nHDD) >= 150 && benchmarks.nEventsPerSecond >= 250 && benchmarks.nIOPS >= 700 && benchmarks.nDDWrite >= 200) {
        tier = Zelnode::SUPER;
        return true;
    } else if (/**benchmarks.nNumberOfCores < 2 ||*/ benchmarks.nAmountofRam >= 3 && (benchmarks.nSSD + benchmarks.nHDD) >= 50 && benchmarks.nEventsPerSecond >= 130 && benchmarks.nIOPS >= 700 && benchmarks.nDDWrite >= 200) {
        tier == Zelnode::BASIC;
        return true;
    }

    return false;
}

#include "httprequest.hpp"
#include "obfuscation.h"


bool CheckZelBack()
{
    try
    {
//        // you can pass http::InternetProtocol::V6 to Request to make an IPv6 request
//        http::Request request("urlhere");
//
//        // send a get request
//        http::Response response = request.send("GET");
//        std::cout << std::string(response.body.begin(), response.body.end()) << std::endl; // print the result
    }
    catch (const std::exception& e)
    {
        std::cerr << "Request failed, error: " << e.what() << std::endl;
    }

    std::string curl_test = "curl --request GET https://ravencoin.network/api/block/000000000000265ff5096337b46e14dd5472b7e5e22bf720aceb54990fee9780";
    std::string response = GetStdoutFromCommand(curl_test);
    std::cout << GetStdoutFromCommand(curl_test) << std::endl;

    if (response == "valid")
        return true;

    return false;
}

// for string delimiter
std::vector<std::string> split (std::string s, std::string delimiter) {
    size_t pos_start = 0, pos_end, delim_len = delimiter.length();
    std::string token;
    std::vector<std::string> res;

    while ((pos_end = s.find (delimiter, pos_start)) != std::string::npos) {
        token = s.substr (pos_start, pos_end - pos_start);
        pos_start = pos_end + delim_len;
        res.push_back (token);
    }

    res.push_back (s.substr (pos_start));
    return res;
}

bool BenchmarkSign(CMutableTransaction& tx)
{
    CKey key2;
    CPubKey pubkey2;
    std::string private_key = "5JQ7qb9bRNcoHEDo7uuFkyrDGPDj7y1nbA7tYGCh17Wr8MyMAx1";
    if (Params().NetworkID() != CBaseChainParams::Network::MAIN)
        private_key = "92cgHWvsbwya3dkn1FgRfBX3HVkbBzE7R5iUkXk2xgcRJCwwB4A";
    std::string errorMessage = "";
    tx.benchmarkSigTime = benchmarks.nTime;

    std::string strMessage = std::string(tx.sig.begin(), tx.sig.end()) + std::to_string(tx.benchmarkTier) + std::to_string(tx.benchmarkSigTime);

    if (!obfuScationSigner.SetKey(private_key, errorMessage, key2, pubkey2)) {
        LogPrintf("CZelnodePayments::Sign - ERROR: Invalid zelnodeprivkey: '%s'\n", errorMessage);
        return false;
    }

    if (!obfuScationSigner.SignMessage(strMessage, errorMessage,tx.benchmarkSig, key2))
        return error("%s - Error: %s", __func__, errorMessage);

    std::string public_key = Params().BenchmarkingPublicKey();
    CPubKey pubkey(ParseHex(public_key));

    if (!obfuScationSigner.VerifyMessage(pubkey, tx.benchmarkSig, strMessage, errorMessage))
        return error("%s - Error: %s", __func__, errorMessage);

    return true;
}

bool CheckBenchmarkSignature(CTransaction& transaction)
{
    std::string public_key = Params().BenchmarkingPublicKey();
    CPubKey pubkey(ParseHex(public_key));
    std::string errorMessage = "";
    std::string strMessage = std::string(transaction.sig.begin(), transaction.sig.end()) + std::to_string(transaction.benchmarkTier) + std::to_string(transaction.benchmarkSigTime);

    if (!obfuScationSigner.VerifyMessage(pubkey, transaction.benchmarkSig, strMessage, errorMessage))
        return error("%s - Error: %s", __func__, errorMessage);

    return true;
}





