#ifndef FIATSHAMIR_H
#define FIATSHAMIR_H

#include <vector>
#include <chrono>

#include "fiatshamirkey.h"

#include "../exceptions.h"
#include "../encoding/cades.h"

namespace D35Crypto
{

class FiatShamir
{
public:
    FiatShamir() { }
    // Sing
    CAdES sign(const std::string &username, const std::vector<uint8_t> &pubKeyHash, const std::string &data,  D35Crypto::HashBase *hash, const FiatShamirKey &key);
    CAdES sign(const std::string &username, const std::vector<uint8_t> &pubKeyHash, const std::string &contentType, const std::vector<uint8_t> &data, D35Crypto::HashBase *hash, const FiatShamirKey &key);
    CAdES sign(const std::string &username, const std::vector<uint8_t> &pubKeyHash, const std::string &contentType, const std::string &filename, D35Crypto::HashBase *hash, const FiatShamirKey &key);    
    void signCA(D35Crypto::CAdES &userCAdES, const std::vector<uint8_t> &caPubKeyHash, const std::vector<uint8_t> &data, const FiatShamirKey &caPrivKey);

    bool checkSign(const std::vector<uint8_t> &data, const D35Crypto::CAdES &cades, const FiatShamirKey &key);
    bool checkCASign(const std::vector<uint8_t> &data, const D35Crypto::CAdES &cades, const FiatShamirKey &caPubKey);
private:
    void sign(std::vector<uint8_t> &signature, const std::vector<uint8_t> &data, const NTL::ZZ &n, const std::vector<NTL::ZZ> &a, HashBase *hash);
};

}

#endif // FIATSHAMIR_H
