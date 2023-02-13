#ifndef FIATSHAMIR_H
#define FIATSHAMIR_H

#include <vector>
#include <chrono>

#include "fiatshamirkey.h"

#include "../exceptions.h"

namespace D35Crypto
{

class FiatShamir
{
public:
    FiatShamir() { }

    template<class T>
    std::vector<uint8_t> sign(const std::vector<uint8_t> &data, const FiatShamirKey &key)
    {
        if (!std::is_base_of_v<HashBase, T>)
        {
            throw std::logic_error("it is necessary that the hash function class inherits from D35Crypto::HashBase");
        }

        NTL::ZZ r = NTL::RandomBnd(key.getN() - 1) + 1; // random r
        NTL::ZZ u = NTL::PowerMod(r, 2, key.getN());    // u = r^2 mod n

        std::vector<uint8_t> uBytes(NTL::NumBytes(u));
        NTL::BytesFromZZ(uBytes.data(), u, uBytes.size());

        std::vector<uint8_t> datarw(data.begin(), data.end());
        datarw.resize(datarw.size() + uBytes.size());
        std::copy(uBytes.begin(), uBytes.end(), datarw.begin() + data.size());

        HashBase* hash = new T();
        hash->update(datarw);       // h(m, u)
        std::vector<uint8_t> signature = hash->digest();
        delete hash;

        std::vector<NTL::ZZ> a = key.getA();
        NTL::ZZ n = key.getN();

        NTL::ZZ t = r; // t = r MUL(i=1,m) a[i] ^ s[i] mod n
        int a_i = 0;
        for (int i = 0; i < signature.size(); i++)
        {
            for (int offset = 0; offset < 8; offset++)
            {
                t = NTL::MulMod(t, NTL::PowerMod(a[a_i], (signature[i] >> offset) & 1, n), n);
                a_i++;
            }
        }

        std::vector<uint8_t> tBytes(NTL::NumBytes(t));
        NTL::BytesFromZZ(tBytes.data(), t, tBytes.size());
        signature.resize(signature.size() + tBytes.size());
        std::copy(tBytes.begin(), tBytes.end(), signature.begin() + (signature.size() - tBytes.size()));

        return signature;
    }

    template<class T>
    bool checkSign(const std::vector<uint8_t> &signature, const std::vector<uint8_t> &data, const FiatShamirKey &key)
    {
        if (!std::is_base_of_v<HashBase, T>)
        {
            throw std::logic_error("it is necessary that the hash function class inherits from D35Crypto::HashBase");
        }

        HashBase* hash = new T();
        hash->update(data);
        std::vector<uint8_t> contentDigest = hash->digest();
        delete hash;

        std::vector<uint8_t> s(signature.begin(), signature.begin() + hash->digestSize());
        std::vector<uint8_t> t(signature.begin() + hash->digestSize(), signature.end());

        NTL::ZZ tInt = NTL::ZZFromBytes(t.data(), t.size());
        NTL::ZZ w = tInt * tInt;
        std::vector<NTL::ZZ> b = key.getB();
        NTL::ZZ n = key.getN();
        int b_i = 0;

        for (int i = 0; i < hash->digestSize(); i++)
        {
            for (int offset = 0; offset < 8; offset++)
            {
                w = NTL::MulMod(w, NTL::PowerMod(b[b_i], (s[i] >> offset) & 1, n), n);
                b_i++;
            }
        }

        std::vector<uint8_t> wBytes(NTL::NumBytes(w));
        NTL::BytesFromZZ(wBytes.data(), w, wBytes.size());
        std::vector<uint8_t> tmpData(data.begin(), data.end());
        tmpData.resize(tmpData.size() + wBytes.size());
        std::copy(wBytes.begin(), wBytes.end(), tmpData.begin() + (tmpData.size() - wBytes.size()));
        hash->update(tmpData);

        return hash->digest() == s;
    }

private:
    void sign(std::vector<uint8_t> &signature, const std::vector<uint8_t> &data, const NTL::ZZ &n, const std::vector<NTL::ZZ> &a, HashBase *hash);
};

}

#endif // FIATSHAMIR_H
