#ifndef PKCS7_H
#define PKCS7_H

#include "ipkcs.h"

namespace MyCryptoLib
{
class PKCS7 : public IPKCS
{
public:
    PKCS7(const std::map<int, std::vector<uint8_t>> &data);
    PKCS7(const std::string &filename);

    std::vector<uint8_t> getData();

    static PKCS7 packEncryptedPKCS7(uint8_t version, const std::string &contentType, const std::string &encryptAlgorythmId, const std::vector<uint8_t> &encryptedData);

    std::vector<uint8_t> toPem()
    {
        return IPKCS::toPem("PKCS7");
    }
private:
    PKCS7() : IPKCS() {}
};

}

#endif // PKCS7_H
