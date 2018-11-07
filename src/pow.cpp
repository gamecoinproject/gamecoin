// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "arith_uint256.h"
#include "chain.h"
#include "primitives/block.h"
#include "uint256.h"

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();
    int64_t nTargetTimespan = params.nPowTargetTimespan;
    int64_t nTargetSpacing = params.nPowTargetSpacing;
    int64_t nInterval = nTargetTimespan / nTargetSpacing;
    int64_t nReTargetHistoryFact = 12;

    // Genesis block
    if (pindexLast == NULL)
        return nProofOfWorkLimit;

    // From block 25200 to 64007, reassess the difficulty every 48 blocks
    if(pindexLast->nHeight >= 25199 && pindexLast->nHeight < 64007)
    {
        nTargetTimespan = 2 * 60 * 60; // 2 hours
        nTargetSpacing = 2.5 * 60; // 2.5 minutes
        nInterval = nTargetTimespan / nTargetSpacing;
    }
    // From block 64008 reassess the difficulty every 12 blocks
    else if(pindexLast->nHeight >= 64007)
    {
        nTargetTimespan = 30 * 60; // 30 minutes
        nTargetSpacing = 2.5 * 60; // 2.5 minutes
        nInterval = nTargetTimespan / nTargetSpacing;
        if(pindexLast->nHeight < 68999)
            nReTargetHistoryFact = 48;
        else
            nReTargetHistoryFact = 4;
    }

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % nInterval != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + nTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % nInterval != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // This fixes an issue where a 51% attack can change difficulty at will.
    // Go back the full period unless it's the first retarget after genesis. Code courtesy of Art Forz
    int blockstogoback = nInterval-1;
    if ((pindexLast->nHeight+1) != nInterval)
        blockstogoback = nInterval;
    if ((pindexLast->nHeight >= 62400 && pindexLast->nHeight < 64000) || pindexLast->nHeight >= 64595)
        blockstogoback = nReTargetHistoryFact * nInterval;

    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < blockstogoback; i++)
        pindexFirst = pindexFirst->pprev;
    assert(pindexFirst);

    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = 0;
    if (pindexLast->nHeight >= 64595)
        nActualTimespan = (pindexLast->GetBlockTime() - pindexFirst->GetBlockTime())/nReTargetHistoryFact;
    else
        nActualTimespan = pindexLast->GetBlockTime() - pindexFirst->GetBlockTime();

    if(pindexLast->nHeight < 25199 || (pindexLast->nHeight >= 60000 && pindexLast->nHeight < 64079))
    {
        if (nActualTimespan < nTargetTimespan/4)
            nActualTimespan = nTargetTimespan/4;
        if (nActualTimespan > nTargetTimespan*4)
            nActualTimespan = nTargetTimespan*4;
    }
    else if(pindexLast->nHeight >= 64079)
    {
        if (nActualTimespan < nTargetTimespan/1.1)
            nActualTimespan = nTargetTimespan/1.1;
        if (nActualTimespan > nTargetTimespan*1.1)
            nActualTimespan = nTargetTimespan*1.1;
    }
    else
    {
        if (nActualTimespan < nTargetTimespan/2)
            nActualTimespan = nTargetTimespan/2;
        if (nActualTimespan > nTargetTimespan*8)
            nActualTimespan = nTargetTimespan*8;
    }

    // Retarget
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bool fShift = bnNew.bits() > 235;
    if (fShift)
        bnNew >>= 1;
    bnNew *= nActualTimespan;
    bnNew /= nTargetTimespan;
    if (fShift)
        bnNew <<= 1;

    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
