// Copyright (c) 2019 The Zelcash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <vector>

#ifndef ZELCASH_BENCHMARKS_H
#define ZELCASH_BENCHMARKS_H

class Benchmarks;
class CMutableTransaction;
class CTransaction;

extern bool fBenchmarkComplete;
extern bool fBenchmarkFailed;
extern bool fBenchmarkRestart;
extern Benchmarks benchmarks;

class Benchmarks {
public:

    int64_t nTime;

    std::string strFailedReason;

    // Nench
    int nNumberOfCores;
    float nAmountofRam;
    float nSSD; // Always in gigabytes
    float nHDD; // Always in gigabytes
    float nIOPS;
    float nDDWrite;

    // Sysbench
    float nEventsPerSecond;
    int nMajorVersion;
    int nMinorVersion;
    int nPatchVersion;
    bool fVersionValid;

    Benchmarks() {
        SetNull();
    }

    void SetNull() {
        nNumberOfCores = 0;
        nAmountofRam = 0;
        nSSD = 0;
        nHDD = 0;
        nIOPS = 0;
        nDDWrite = 0;
        nEventsPerSecond = 0;
        nMajorVersion = 0;
        nMinorVersion = 0;
        nPatchVersion = 0;
        fVersionValid = false;
        nTime = 0;
        strFailedReason = "";
    }

    bool IsNenchCheckComplete();
    bool IsSysBenchCheckComplete();
    std::string NenchResultToString();
    std::string ToString();

    std::string GetSysbenchVersion();
};

bool CheckBenchmarks(int& tier);
bool CheckZelBack();

void ThreadBenchmarkZelnode();

void SetupSysBench();
bool CheckSysBenchInstalled();
bool CheckSysBenchVersion();
void RunSysBenchTest();
void RunNenchTest();
void InstallSysBenchPackage();
void InstallSysBench_1();
void InstallSysBench_2();

std::string GetStdoutFromCommand(std::string cmd);


// Parsing help functions
std::vector<std::string> split(std::string s, std::string delimiter);

bool BenchmarkSign(CMutableTransaction& tx);
bool CheckBenchmarkSignature(CTransaction& transaction);

static std::string strNenchScript= "#!/usr/bin/env bash\n"
                            "\n"
                            "##########\n"
                            "# nench.sh (\"new bench.sh\")\n"
                            "# =========================\n"
                            "# current version at https://github.com/n-st/nench\n"
                            "# - loosely based on the established freevps.us/bench.sh\n"
                            "# - includes CPU and ioping measurements\n"
                            "# - reduced number of speedtests (9 x 100 MB), while retaining useful European\n"
                            "#   and North American POPs\n"
                            "# - runs IPv6 speedtest by default (if the server has IPv6 connectivity)\n"
                            "# Run using `curl -s bench.wget.racing | bash`\n"
                            "# or `wget -qO- bench.wget.racing | bash`\n"
                            "# - list of possibly required packages: curl,gawk,coreutils,util-linux,procps,ioping\n"
                            "##########\n"
                            "\n"
                            "command_exists()\n"
                            "{\n"
                            "    command -v \"$@\" > /dev/null 2>&1\n"
                            "}\n"
                            "\n"
                            "Bps_to_MiBps()\n"
                            "{\n"
                            "    awk '{ printf \"%.2f MiB/s\\n\", $0 / 1024 / 1024 } END { if (NR == 0) { print \"error\" } }'\n"
                            "}\n"
                            "\n"
                            "B_to_MiB()\n"
                            "{\n"
                            "    awk '{ printf \"%.0f MiB\\n\", $0 / 1024 / 1024 } END { if (NR == 0) { print \"error\" } }'\n"
                            "}\n"
                            "\n"
                            "redact_ip()\n"
                            "{\n"
                            "    case \"$1\" in\n"
                            "        *.*)\n"
                            "            printf '%s.xxxx\\n' \"$(printf '%s\\n' \"$1\" | cut -d . -f 1-3)\"\n"
                            "            ;;\n"
                            "        *:*)\n"
                            "            printf '%s:xxxx\\n' \"$(printf '%s\\n' \"$1\" | cut -d : -f 1-3)\"\n"
                            "            ;;\n"
                            "    esac\n"
                            "}\n"
                            "\n"
                            "finish()\n"
                            "{\n"
                            "    printf '\\n'\n"
                            "    rm -f test_$$\n"
                            "    exit\n"
                            "}\n"
                            "# make sure the dd test file is always deleted, even when the script is\n"
                            "# interrupted while dd is running\n"
                            "trap finish EXIT INT TERM\n"
                            "\n"
                            "command_benchmark()\n"
                            "{\n"
                            "    if [ \"$1\" = \"-q\" ]\n"
                            "    then\n"
                            "        QUIET=1\n"
                            "        shift\n"
                            "    fi\n"
                            "\n"
                            "    if command_exists \"$1\"\n"
                            "    then\n"
                            "        time \"$gnu_dd\" if=/dev/zero bs=1M count=500 2> /dev/null | \\\n"
                            "            \"$@\" > /dev/null\n"
                            "    else\n"
                            "        if [ \"$QUIET\" -ne 1 ]\n"
                            "        then\n"
                            "            unset QUIET\n"
                            "            printf '[command `%s` not found]\\n' \"$1\"\n"
                            "        fi\n"
                            "        return 1\n"
                            "    fi\n"
                            "}\n"
                            "\n"
                            "dd_benchmark()\n"
                            "{\n"
                            "    # returns IO speed in B/s\n"
                            "\n"
                            "    # Temporarily override locale to deal with non-standard decimal separators\n"
                            "    # (e.g. \",\" instead of \".\").\n"
                            "    # The awk script assumes bytes/second if the suffix is !~ [TGMK]B. Call me\n"
                            "    # if your storage system does more than terabytes per second; I'll want to\n"
                            "    # see that.\n"
                            "    LC_ALL=C \"$gnu_dd\" if=/dev/zero of=test_$$ bs=64k count=16k conv=fdatasync 2>&1 | \\\n"
                            "        awk -F, '\n"
                            "            {\n"
                            "                io=$NF\n"
                            "            }\n"
                            "            END {\n"
                            "                if (io ~ /TB\\/s/) {printf(\"%.0f\\n\", 1000*1000*1000*1000*io)}\n"
                            "                else if (io ~ /GB\\/s/) {printf(\"%.0f\\n\", 1000*1000*1000*io)}\n"
                            "                else if (io ~ /MB\\/s/) {printf(\"%.0f\\n\", 1000*1000*io)}\n"
                            "                else if (io ~ /KB\\/s/) {printf(\"%.0f\\n\", 1000*io)}\n"
                            "                else { printf(\"%.0f\", 1*io)}\n"
                            "            }'\n"
                            "    rm -f test_$$\n"
                            "}\n"
                            "\n"
                            "download_benchmark()\n"
                            "{\n"
                            "    curl --max-time 10 -so /dev/null -w '%{speed_download}\\n' \"$@\"\n"
                            "}\n"
                            "\n"
                            "if ! command_exists curl\n"
                            "then\n"
                            "    printf '%s\\n' 'This script requires curl, but it could not be found.' 1>&2\n"
                            "    exit 1\n"
                            "fi\n"
                            "\n"
                            "if command_exists gdd\n"
                            "then\n"
                            "    gnu_dd='gdd'\n"
                            "elif command_exists dd\n"
                            "then\n"
                            "    gnu_dd='dd'\n"
                            "else\n"
                            "    printf '%s\\n' 'This script requires dd, but it could not be found.' 1>&2\n"
                            "    exit 1\n"
                            "fi\n"
                            "\n"
                            "if ! \"$gnu_dd\" --version > /dev/null 2>&1\n"
                            "then\n"
                            "    printf '%s\\n' 'It seems your system only has a non-GNU version of dd.'\n"
                            "    printf '%s\\n' 'dd write tests disabled.'\n"
                            "    gnu_dd=''\n"
                            "fi\n"
                            "\n"
                            "printf '%s\\n' '-------------------------------------------------'\n"
                            "printf ' nench.sh v2018.04.14 -- https://git.io/nench.sh\\n'\n"
                            "date -u '+ benchmark timestamp:    %F %T UTC'\n"
                            "printf '%s\\n' '-------------------------------------------------'\n"
                            "\n"
                            "printf '\\n'\n"
                            "\n"
                            "if ! command_exists ioping\n"
                            "then\n"
                            "    curl -s --max-time 10 -o ioping.static http://wget.racing/ioping.static\n"
                            "    chmod +x ioping.static\n"
                            "    ioping_cmd=\"./ioping.static\"\n"
                            "else\n"
                            "    ioping_cmd=\"ioping\"\n"
                            "fi\n"
                            "\n"
                            "# Basic info\n"
                            "if [ \"$(uname)\" = \"Linux\" ]\n"
                            "then\n"
                            "    printf 'Processor:    '\n"
                            "    awk -F: '/model name/ {name=$2} END {print name}' /proc/cpuinfo | sed 's/^[ \\t]*//;s/[ \\t]*$//'\n"
                            "    printf 'CPU cores:    '\n"
                            "    awk -F: '/model name/ {core++} END {print core}' /proc/cpuinfo\n"
                            "    printf 'Frequency:    '\n"
                            "    awk -F: ' /cpu MHz/ {freq=$2} END {print freq \" MHz\"}' /proc/cpuinfo | sed 's/^[ \\t]*//;s/[ \\t]*$//'\n"
                            "    printf 'RAM:          '\n"
                            "    free -h | awk 'NR==2 {print $2}'\n"
                            "    if [ \"$(swapon -s | wc -l)\" -lt 2 ]\n"
                            "    then\n"
                            "        printf 'Swap:         -\\n'\n"
                            "    else\n"
                            "        printf 'Swap:         '\n"
                            "        free -h | awk '/Swap/ {printf $2}'\n"
                            "        printf '\\n'\n"
                            "    fi\n"
                            "else\n"
                            "    # we'll assume FreeBSD, might work on other BSDs too\n"
                            "    printf 'Processor:    '\n"
                            "    sysctl -n hw.model\n"
                            "    printf 'CPU cores:    '\n"
                            "    sysctl -n hw.ncpu\n"
                            "    printf 'Frequency:    '\n"
                            "    grep -Eo -- '[0-9.]+-MHz' /var/run/dmesg.boot | tr -- '-' ' '\n"
                            "    printf 'RAM:          '\n"
                            "    sysctl -n hw.physmem | B_to_MiB\n"
                            "\n"
                            "    if [ \"$(swapinfo | wc -l)\" -lt 2 ]\n"
                            "    then\n"
                            "        printf 'Swap:         -\\n'\n"
                            "    else\n"
                            "        printf 'Swap:         '\n"
                            "        swapinfo -k | awk 'NR>1 && $1!=\"Total\" {total+=$2} END {print total*1024}' | B_to_MiB\n"
                            "    fi\n"
                            "fi\n"
                            "printf 'Kernel:       '\n"
                            "uname -s -r -m\n"
                            "\n"
                            "printf '\\n'\n"
                            "\n"
                            "printf 'Disks:\\n'\n"
                            "if command_exists lsblk && [ -n \"$(lsblk)\" ]\n"
                            "then\n"
                            "    lsblk --nodeps --noheadings --output NAME,SIZE,ROTA --exclude 1,2,11 | sort | awk '{if ($3 == 0) {$3=\"SSD\"} else {$3=\"HDD\"}; printf(\"%-3s%8s%5s\\n\", $1, $2, $3)}'\n"
                            "elif [ -r \"/var/run/dmesg.boot\" ]\n"
                            "then\n"
                            "    awk '/(ad|ada|da|vtblk)[0-9]+: [0-9]+.B/ { print $1, $2/1024, \"GiB\" }' /var/run/dmesg.boot\n"
                            "elif command_exists df\n"
                            "then\n"
                            "    df -h --output=source,fstype,size,itotal | awk 'NR == 1 || /^\\/dev/'\n"
                            "else\n"
                            "    printf '[ no data available ]'\n"
                            "fi\n"
                            "\n"
                            "printf '\\n'\n"
                            "\n"
                            "# CPU tests\n"
                            "export TIMEFORMAT='%3R seconds'\n"
                            "\n"
                            "printf 'CPU: SHA256-hashing 500 MB\\n    '\n"
                            "command_benchmark -q sha256sum || command_benchmark -q sha256 || printf '[no SHA256 command found]\\n'\n"
                            "\n"
                            "printf 'CPU: bzip2-compressing 500 MB\\n    '\n"
                            "command_benchmark bzip2\n"
                            "\n"
                            "printf 'CPU: AES-encrypting 500 MB\\n    '\n"
                            "command_benchmark openssl enc -e -aes-256-cbc -pass pass:12345678\n"
                            "\n"
                            "printf '\\n'\n"
                            "\n"
                            "# ioping\n"
                            "printf 'ioping: seek rate\\n    '\n"
                            "\"$ioping_cmd\" -DR -w 5 . | tail -n 1\n"
                            "printf 'ioping: sequential read speed\\n    '\n"
                            "\"$ioping_cmd\" -DRL -w 5 . | tail -n 2 | head -n 1\n"
                            "\n"
                            "printf '\\n'\n"
                            "\n"
                            "# dd disk test\n"
                            "printf 'dd: sequential write speed\\n'\n"
                            "\n"
                            "if [ -z \"$gnu_dd\" ]\n"
                            "then\n"
                            "    printf '    %s\\n' '[disabled due to missing GNU dd]'\n"
                            "else\n"
                            "    io1=$( dd_benchmark )\n"
                            "    printf '    1st run:    %s\\n' \"$(printf '%d\\n' \"$io1\" | Bps_to_MiBps)\"\n"
                            "\n"
                            "    io2=$( dd_benchmark )\n"
                            "    printf '    2nd run:    %s\\n' \"$(printf '%d\\n' \"$io2\" | Bps_to_MiBps)\"\n"
                            "\n"
                            "    io3=$( dd_benchmark )\n"
                            "    printf '    3rd run:    %s\\n' \"$(printf '%d\\n' \"$io3\" | Bps_to_MiBps)\"\n"
                            "\n"
                            "    # Calculating avg I/O (better approach with awk for non int values)\n"
                            "    ioavg=$( awk 'BEGIN{printf(\"%.0f\", ('\"$io1\"' + '\"$io2\"' + '\"$io3\"')/3)}' )\n"
                            "    printf '    average:    %s\\n' \"$(printf '%d\\n' \"$ioavg\" | Bps_to_MiBps)\"\n"
                            "fi\n"
                            "\n"
                            "printf '\\n'\n"
                            "\n"
                            "# Network speedtests\n"
                            "\n"
                            "ipv4=$(curl -4 -s --max-time 5 http://icanhazip.com/)\n"
                            "if [ -n \"$ipv4\" ]\n"
                            "then\n"
                            "    printf 'IPv4 speedtests\\n'\n"
                            "    printf '    your IPv4:    %s\\n' \"$(redact_ip \"$ipv4\")\"\n"
                            "    printf '\\n'\n"
                            "\n"
                            "    printf '    Cachefly CDN:         '\n"
                            "    download_benchmark -4 http://cachefly.cachefly.net/100mb.test | \\\n"
                            "        Bps_to_MiBps\n"
                            "\n"
                            "    printf '    Leaseweb (NL):        '\n"
                            "    download_benchmark -4 http://mirror.nl.leaseweb.net/speedtest/100mb.bin | \\\n"
                            "        Bps_to_MiBps\n"
                            "\n"
                            "    printf '    Softlayer DAL (US):   '\n"
                            "    download_benchmark -4 http://speedtest.dal01.softlayer.com/downloads/test100.zip | \\\n"
                            "        Bps_to_MiBps\n"
                            "\n"
                            "    printf '    Online.net (FR):      '\n"
                            "    download_benchmark -4 http://ping.online.net/100Mo.dat | \\\n"
                            "        Bps_to_MiBps\n"
                            "\n"
                            "    printf '    OVH BHS (CA):         '\n"
                            "    download_benchmark -4 http://proof.ovh.ca/files/100Mio.dat | \\\n"
                            "        Bps_to_MiBps\n"
                            "\n"
                            "else\n"
                            "    printf 'No IPv4 connectivity detected\\n'\n"
                            "fi\n"
                            "\n"
                            "printf '\\n'\n"
                            "\n"
                            "ipv6=$(curl -6 -s --max-time 5 http://icanhazip.com/)\n"
                            "if [ -n \"$ipv6\" ]\n"
                            "then\n"
                            "    printf 'IPv6 speedtests\\n'\n"
                            "    printf '    your IPv6:    %s\\n' \"$(redact_ip \"$ipv6\")\"\n"
                            "    printf '\\n'\n"
                            "\n"
                            "    printf '    Leaseweb (NL):        '\n"
                            "    download_benchmark -6 http://mirror.nl.leaseweb.net/speedtest/100mb.bin | \\\n"
                            "        Bps_to_MiBps\n"
                            "\n"
                            "    printf '    Softlayer DAL (US):   '\n"
                            "    download_benchmark -6 http://speedtest.dal01.softlayer.com/downloads/test100.zip | \\\n"
                            "        Bps_to_MiBps\n"
                            "\n"
                            "    printf '    Online.net (FR):      '\n"
                            "    download_benchmark -6 http://ping6.online.net/100Mo.dat | \\\n"
                            "        Bps_to_MiBps\n"
                            "\n"
                            "    printf '    OVH BHS (CA):         '\n"
                            "    download_benchmark -6 http://proof.ovh.ca/files/100Mio.dat | \\\n"
                            "        Bps_to_MiBps\n"
                            "\n"
                            "else\n"
                            "    printf 'No IPv6 connectivity detected\\n'\n"
                            "fi\n"
                            "\n"
                            "printf '%s\\n' '-------------------------------------------------'\n"
                            "\n"
                            "# delete downloaded ioping binary if script has been run straight from a pipe\n"
                            "# (rather than a downloaded file)\n"
                            "[ -t 0 ] || rm -f ioping.static";


#endif //ZELCASH_BENCHMARKS_H
