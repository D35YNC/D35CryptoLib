#ifndef ELGAMAL_H
#define ELGAMAL_H

#include <vector>
#include <chrono>

#include "elgamalkey.h"

#include "../exceptions.h"
#include "../encoding/cades.h"

namespace MyCryptoLib
{

class ElGamal
{
public:
    ElGamal() { };

    // Sing
    CAdES sign(const std::string &username, const std::vector<uint8_t> &pubKeyHash, const std::string &data, MyCryptoLib::HashBase *hash, const ElGamalKey &key);
    CAdES sign(const std::string &username, const std::vector<uint8_t> &pubKeyHash, const std::string &contentType, const std::vector<uint8_t> &data, MyCryptoLib::HashBase *hash, const ElGamalKey &key);
    CAdES sign(const std::string &username, const std::vector<uint8_t> &pubKeyHash, const std::string &contentType, const std::string &filename, MyCryptoLib::HashBase *hash, const ElGamalKey &key);
    void signCA(MyCryptoLib::CAdES &userCAdES, const std::vector<uint8_t> &caPubKeyHash, const std::vector<uint8_t> &data, const ElGamalKey &caPrivKey);

    bool checkSign(const std::vector<uint8_t> &data, const MyCryptoLib::CAdES &pkcs7obj, const ElGamalKey &key);
    bool checkCASign(const std::vector<uint8_t> &data, const MyCryptoLib::CAdES &pkcs7obj, const ElGamalKey &caPubKey);
private:
    void sign(std::vector<uint8_t> &signature, NTL::ZZ a, NTL::ZZ alpha, NTL::ZZ p);
};

}

#endif // ELGAMAL_H
