#ifndef FIATSHAMIRKEY_H
#define FIATSHAMIRKEY_H

#include <vector>
#include <string>
#include <sstream>
#include <random>
#include <fstream>
#include <algorithm>

#include <NTL/ZZ.h>

#include "../exceptions.h"

#include "../hash/hash_base.h"
#include "../hash/sha256.h"
#include "../hash/sha512.h"
#include "../hash/streebog.h"
#include "../encoding/base64.h"


namespace D35Crypto
{
class FiatShamirKey
{
public:
    // For generation & custom params
    FiatShamirKey(NTL::ZZ _p, NTL::ZZ _q, NTL::ZZ _n, std::vector<NTL::ZZ> _a, std::vector<NTL::ZZ> _b) :
        p(_p), q(_q), n(_n), a(_a), b(_b)
    { }
    // For custom pub key
    FiatShamirKey(NTL::ZZ _n, std::vector<NTL::ZZ> _b) :
        n(_n), p(NTL::conv<NTL::ZZ>(0)), q(NTL::conv<NTL::ZZ>(0)),
        a({}), b(_b)
    { }
    // For custom priv key & extract pubkey
    FiatShamirKey(NTL::ZZ _p, NTL::ZZ _q, std::vector<NTL::ZZ> _a) :
        n(_p * _q), p(_p), q(_q), a(_a), b({})
    {
        this->b.resize(_a.size());
        for (int i = 0; i < this->b.size(); i++)
        {
            b[i] = NTL::PowerMod(NTL::InvMod(a[i], n), 2, n);
        }
    }

    template<class T>
    static FiatShamirKey generate(size_t bitSize)
    {
        static_assert(std::is_base_of_v<HashBase, T>, "FiatShamirKey generate: it is necessary that the hash function class inherits from D35Crypto::HashBase");
// add hash id check
        NTL::ZZ p;
        NTL::ZZ q;
        NTL::ZZ n;
        NTL::ZZ tmp = NTL::conv<NTL::ZZ>(0);

        HashBase *hash = new T();
        size_t i_count = hash->digestSize() * 8;
        delete hash;

        std::vector<NTL::ZZ> a(i_count);
        std::vector<NTL::ZZ> b(i_count);

        if (bitSize % 1024 != 0)
        {
            throw D35Crypto::BadKeySizeException(__LINE__, __FILE__);
        }

        // Generating 512 bytes seed
        std::vector<unsigned char> seed(512, 0x00);
        std::uniform_int_distribution<uint64_t> dist(0, UINT64_MAX - 1);
        std::random_device dev_random("/dev/random");
        for (int i = 0; i < seed.size(); i++)
        {
            seed[i] = dist(dev_random);
        }
        NTL::SetSeed(seed.data(), seed.size());

        // random pq
        p = NTL::GenPrime_ZZ(static_cast<long>(bitSize / 2));
        q = NTL::GenPrime_ZZ(static_cast<long>(bitSize / 2));
        n = p * q;

        for (int i = 0; i < i_count; i++)
        {
            do
            {
                tmp = NTL::RandomBnd(n); // random A[i]. GCD(a, n) == 1
            } while (NTL::GCD(tmp, n) != NTL::conv<NTL::ZZ>(1));
            a[i] = tmp;
        }

        for (int i = 0; i < i_count; i++)
        {
            tmp = NTL::PowerMod(NTL::InvMod(a[i], n), 2, n); // b[i] = (a[i]^-1) ^ 2 mod n
            b[i] = tmp;
        }

        return D35Crypto::FiatShamirKey(p, q, n, a, b);
    }

//    static FiatShamirKey pubKeyFromBytes(const std::vector<uint8_t> &buffer, bool skipHeaders = false);
//    static FiatShamirKey privateKeyFromBytes(const std::vector<uint8_t> &buffer, bool skipHeaders = false);

    bool isPrivate() const noexcept;
    bool canSign() const noexcept;
    bool canEncrypt() const noexcept;
    bool canDecrypt() const noexcept;
    size_t blockSize() const;
    size_t size() const;

    std::vector<uint8_t> exportPrivateKeyBytes() const;
    std::vector<uint8_t> exportPublicKeyBytes() const;

    NTL::ZZ getP() const;
    NTL::ZZ getQ() const;
    NTL::ZZ getN() const;
    std::vector<NTL::ZZ> getA() const;
    std::vector<NTL::ZZ> getB() const;

private:
    NTL::ZZ p; // prime
    NTL::ZZ q; // prime
    NTL::ZZ n; // = p * q
    std::vector<NTL::ZZ> a; // random
    std::vector<NTL::ZZ> b; // (ai^-1(mod n) )^2 (mod n)
};

}
#endif // FIATSHAMIRKEY_H
