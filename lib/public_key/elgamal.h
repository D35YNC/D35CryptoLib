#ifndef ELGAMAL_H
#define ELGAMAL_H

#include <vector>

#include "elgamalkey.h"

#include "../exceptions.h"
#include "../hash/hash_base.h"

namespace D35Crypto
{

class ElGamal
{
public:
    ElGamal() { };

    template<class T>
    std::vector<uint8_t> sign(const std::vector<uint8_t> &data, const ElGamalKey &key)
    {
        static_assert (std::is_base_of_v<HashBase, T>, "it is necessary that the hash function class inherits from D35Crypto::HashBase");

        HashBase* hash = new T();

        hash->update(data);
        std::vector<uint8_t> signature = hash->digest();

        delete hash;

        NTL::ZZ signatureInt = NTL::ZZFromBytes(signature.data(), signature.size());

        NTL::ZZ r;
        NTL::ZZ gcdResult;
        NTL::ZZ gcdA;
        NTL::ZZ gcdB;

        while (gcdResult != NTL::conv<NTL::ZZ>(1))
        {
            r = NTL::RandomBnd(key.getP() - 2);
            NTL::XGCD(gcdResult, gcdA, gcdB, r, key.getP() - 1);
        }

        NTL::ZZ gamma = NTL::PowerMod(key.getAlpha(), r, key.getP());
        NTL::ZZ delta = NTL::MulMod(signatureInt - (key.getA() * gamma), gcdA, key.getP() - 1);

        signature.resize(key.size() * 2);
        NTL::BytesFromZZ(&signature.data()[key.size() - NTL::NumBytes(gamma)], gamma, NTL::NumBytes(gamma));
        NTL::BytesFromZZ(&signature.data()[(key.size() * 2) - NTL::NumBytes(delta)], delta, NTL::NumBytes(delta));

        return signature;
    }

    template<class T>
    bool checkSign(const std::vector<uint8_t> &signature, const std::vector<uint8_t> &data, const ElGamalKey &key)
    {
        static_assert (std::is_base_of_v<HashBase, T>, "it is necessary that the hash function class inherits from D35Crypto::HashBase");

        HashBase* hash = new T();
        hash->update(data);
        std::vector<uint8_t> contentDigest = hash->digest();
        delete hash;

        NTL::ZZ contentDigestInt = NTL::ZZFromBytes(contentDigest.data(), contentDigest.size());

        // extract gamma-delta
        NTL::ZZ gamma = NTL::ZZFromBytes(&signature.data()[0], static_cast<long>(signature.size() / 2));
        NTL::ZZ delta = NTL::ZZFromBytes(&signature.data()[static_cast<long>(signature.size() / 2)], static_cast<long>(signature.size() / 2));

        NTL::ZZ stage0 = NTL::PowerMod(key.getBeta(), gamma, key.getP()); // beta^gamma mod p
        NTL::ZZ stage1 = NTL::PowerMod(gamma, delta, key.getP());         // gamma^delta modp
        NTL::ZZ stage2 = NTL::MulMod(stage0, stage1, key.getP());         // beta^gamma * gamma^delta modp
        NTL::ZZ stage3 = NTL::PowerMod(key.getAlpha(), contentDigestInt, key.getP()); // alpha ^ hash(data) mod p
                                                                            // if stg2 == stg3 => SUCC

        contentDigestInt = NTL::PowerMod(key.getAlpha(), contentDigestInt, key.getP());

        return stage2 == stage3 && stage2 == contentDigestInt;
    }
};

}

#endif // ELGAMAL_H
