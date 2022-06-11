#ifndef RSA_H
#define RSA_H

#include <vector>
#include <chrono> // for timestamp

#include "rsakey.h"

#include "../exceptions.h"
#include "../encoding/pkcs7.h"
#include "../encoding/cades.h"
#include "../hash/hash_base.h" // for sign

namespace MyCryptoLib
{
class RSA
{
public:
    RSA() { }

    std::vector<uint8_t> encrypt(const std::vector<uint8_t> &data, const RSAKey &key);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t> &data, const RSAKey &key);

    // PKCS
    PKCS7 encrypt(const std::string &dataType, const std::vector<uint8_t> &data, const RSAKey &key);
    std::vector<uint8_t> decrypt(const PKCS7 &pkcs7obj, const RSAKey &key);

    // Sing
    CAdES sign(const std::string &username, const std::vector<uint8_t> &pubKeyHash, const std::string &data, MyCryptoLib::HashBase *hash, const RSAKey &key);
    CAdES sign(const std::string &username, const std::vector<uint8_t> &pubKeyHash, const std::string &contentType, const std::vector<uint8_t> &data, MyCryptoLib::HashBase *hash, const RSAKey &key);
    CAdES sign(const std::string &username, const std::vector<uint8_t> &pubKeyHash, const std::string &contentType, const std::string &filename, MyCryptoLib::HashBase *hash, const RSAKey &key);
    void signCA(MyCryptoLib::CAdES &userCAdES, const std::vector<uint8_t> &caPubKeyHash, const std::vector<uint8_t> &data, const RSAKey &key);

    bool checkSign(const std::vector<uint8_t> &data, const MyCryptoLib::CAdES &cades, const RSAKey &key);
    bool checkCASign(const std::vector<uint8_t> &data, const MyCryptoLib::CAdES &cades, const RSAKey &caPubKey);
private:
    void crypt(std::vector<uint8_t> &data, const NTL::ZZ &power, const NTL::ZZ &n);
    void pad(std::vector<uint8_t> &data, size_t blockSize);
    void unpad(std::vector<uint8_t> &data);
};
}


#endif // RSA_H
