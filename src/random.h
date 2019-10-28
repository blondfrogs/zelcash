// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RANDOM_H
#define BITCOIN_RANDOM_H

#include "uint256.h"

#include <functional>
#include <stdint.h>

/**
 * Functions to gather random data via the libsodium CSPRNG
 */
void GetRandBytes(unsigned char* buf, size_t num);
uint64_t GetRand(uint64_t nMax);
int GetRandInt(int nMax);
uint256 GetRandHash();


/* Number of random bytes returned by GetOSRand.
 * When changing this constant make sure to change all call sites, and make
 * sure that the underlying OS APIs for all platforms support the number.
 * (many cap out at 256 bytes).
 */
static const ssize_t NUM_OS_RANDOM_BYTES = 32;

/**
 * Function to gather random data from multiple sources, failing whenever any
 * of those source fail to provide a result.
 */
void GetStrongRandBytes(unsigned char* buf, int num);
/* Seed OpenSSL PRNG with additional entropy data */
void RandAddSeed();
/** Get 32 bytes of system entropy. Do not use this in application code: use
 * GetStrongRandBytes instead.
 */
void GetOSRand(unsigned char *ent32);


/** Check that OS randomness is available and returning the requested number
 * of bytes.
 */
bool Random_SanityCheck();

/**
 * Fast randomness source. This is seeded once with secure random data, but
 * is completely deterministic and insecure after that.
 * This class is not thread-safe.
 */
class FastRandomContext {
public:
    explicit FastRandomContext(bool fDeterministic=false);

    uint32_t rand32() {
        Rz = 36969 * (Rz & 65535) + (Rz >> 16);
        Rw = 18000 * (Rw & 65535) + (Rw >> 16);
        return (Rw << 16) + Rz;
    }

    uint32_t rand32(uint32_t nMax) {
        return rand32() % nMax;
    }

    uint32_t operator()(uint32_t nMax) {
        return rand32(nMax);
    }

    uint32_t Rz;
    uint32_t Rw;
};

/**
 * Identity function for MappedShuffle, so that elements retain their original order.
 */
 int GenIdentity(int n);

/**
 * Rearranges the elements in the range [first,first+len) randomly, assuming
 * that gen is a uniform random number generator. Follows the same algorithm as
 * std::shuffle in C++11 (a Durstenfeld shuffle).
 *
 * The elements in the range [mapFirst,mapFirst+len) are rearranged according to
 * the same permutation, enabling the permutation to be tracked by the caller.
 *
 * gen takes an integer n and produces a uniform random output in [0,n).
 */
template <typename RandomAccessIterator, typename MapRandomAccessIterator>
void MappedShuffle(RandomAccessIterator first,
                   MapRandomAccessIterator mapFirst,
                   size_t len,
                   std::function<int(int)> gen)
{
    for (size_t i = len-1; i > 0; --i) {
        auto r = gen(i+1);
        assert(r >= 0);
        assert(r <= i);
        std::swap(first[i], first[r]);
        std::swap(mapFirst[i], mapFirst[r]);
    }
}

/**
 * Seed insecure_rand using the random pool.
 * @param Deterministic Use a deterministic seed
 */
void seed_insecure_rand(bool fDeterministic = false);

/**
 * MWC RNG of George Marsaglia
 * This is intended to be fast. It has a period of 2^59.3, though the
 * least significant 16 bits only have a period of about 2^30.1.
 *
 * @return random value
 */
extern uint32_t insecure_rand_Rz;
extern uint32_t insecure_rand_Rw;
static inline uint32_t insecure_rand(void)
{
    insecure_rand_Rz = 36969 * (insecure_rand_Rz & 65535) + (insecure_rand_Rz >> 16);
    insecure_rand_Rw = 18000 * (insecure_rand_Rw & 65535) + (insecure_rand_Rw >> 16);
    return (insecure_rand_Rw << 16) + insecure_rand_Rz;
}

#endif // BITCOIN_RANDOM_H
