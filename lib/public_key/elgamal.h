#ifndef ELGAMAL_H
#define ELGAMAL_H

#include <vector>
#include <chrono>

#include "elgamalkey.h"

#include "../exceptions.h"
#include "../encoding/cades.h"

namespace D35Crypto
{

class ElGamal
{
public:
    ElGamal() { };

    // Sing
    CAdES sign(const std::string &username, const std::vector<uint8_t> &pubKeyHash, const std::string &data, D35Crypto::HashBase *hash, const ElGamalKey &key);
    CAdES sign(const std::string &username, const std::vector<uint8_t> &pubKeyHash, const std::string &contentType, const std::vector<uint8_t> &data, D35Crypto::HashBase *hash, const ElGamalKey &key);
    CAdES sign(const std::string &username, const std::vector<uint8_t> &pubKeyHash, const std::string &contentType, const std::string &filename, D35Crypto::HashBase *hash, const ElGamalKey &key);
    void signCA(D35Crypto::CAdES &userCAdES, const std::vector<uint8_t> &caPubKeyHash, const std::vector<uint8_t> &data, const ElGamalKey &caPrivKey);

    bool checkSign(const std::vector<uint8_t> &signedMessage, const D35Crypto::CAdES &cades, const ElGamalKey &pubKey);
    bool checkCASign(const std::vector<uint8_t> &signedMessage, const D35Crypto::CAdES &cades, const ElGamalKey &caPubKey);
private:
    void sign(std::vector<uint8_t> &signature, NTL::ZZ a, NTL::ZZ alpha, NTL::ZZ p);
};

}

#endif // ELGAMAL_H
