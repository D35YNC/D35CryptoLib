#ifndef RSA_H
#define RSA_H

#include <vector>

#include "rsakey.h"

#include "../hash/ihash.h"
#include "../exceptions.h"
#include "../encoding/pkcs7.h"


namespace MyCryptoLib
{
class RSA
{
public:
    RSA() { }

    std::vector<uint8_t> encrypt(const std::vector<uint8_t> &data, const RSAKey &key);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t> &data, const RSAKey &key);

    // PKCS7
    PKCS7 encrypt(const std::string &dataType, const std::vector<uint8_t> &data, const RSAKey &key);
    std::vector<uint8_t> decrypt(const PKCS7 &pkcs7obj, const RSAKey &key);

    PKCS7 sign(const std::string &dataType, const std::vector<uint8_t> &data, const RSAKey &key);
    bool checkSign(const PKCS7 &pkcs7obj, const RSAKey &key);
private:
    void crypt(std::vector<uint8_t> &data, const NTL::ZZ &power, const NTL::ZZ &n);
    void pad(std::vector<uint8_t> &data, size_t blockSize);
};
}


#endif // RSA_H
