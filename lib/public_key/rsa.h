#ifndef RSA_H
#define RSA_H

#include <vector>

#include "rsakey.h"

#include "../exceptions.h"
#include "../hash/hash_base.h"

namespace D35Crypto
{
class RSA
{
public:
    RSA() { }

    std::vector<uint8_t> encrypt(const std::vector<uint8_t> &data, const RSAKey &key);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t> &data, const RSAKey &key);

    template<class T>
    std::vector<uint8_t> sign(const std::vector<uint8_t> &data, const RSAKey &key)
    {
        static_assert(std::is_base_of_v<HashBase, T>, "RSA Sign: it is necessary that the hash function class inherits from D35Crypto::HashBase");

        HashBase *hash = new T();

        hash->update(data);
        std::vector<uint8_t> signature = hash->digest();
        this->crypt(signature, key.getPrivateExponent(), key.getModulus());

        delete hash;

        return signature;
    }

    template<class T>
    bool checkSign(const std::vector<uint8_t> &signature, const std::vector<uint8_t> &data, const RSAKey &key)
    {
        static_assert(std::is_base_of_v<HashBase, T>, "RSA CheckSign: it is necessary that the hash function class inherits from D35Crypto::HashBase");

        HashBase *hash = new T();

        hash->update(data);
        std::vector<uint8_t> dataDigest = hash->digest();

        delete hash;

        std::vector<uint8_t> tmp = signature; // fuck it
        this->crypt(tmp, key.getPublicExponent(), key.getModulus());
        tmp.resize(dataDigest.size());

        return tmp == dataDigest;
    }

private:
    void crypt(std::vector<uint8_t> &data, const NTL::ZZ &power, const NTL::ZZ &n);
    void pad(std::vector<uint8_t> &data, size_t blockSize);
    void unpad(std::vector<uint8_t> &data);
};
}


#endif // RSA_H
