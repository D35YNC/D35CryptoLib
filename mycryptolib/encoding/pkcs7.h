#ifndef PKCS7_H
#define PKCS7_H

#include "pkcs_base.h"
#include "../exceptions.h"

namespace MyCryptoLib
{
class PKCS7 : public PKCSBase
{
public:
    PKCS7(const std::string &filename);
    PKCS7(const std::map<int, std::vector<uint8_t>> &data);

    std::vector<uint8_t> getData() const;

    static PKCS7 packEncryptedPKCS7(uint8_t version, const std::string &contentType, const std::string &encryptAlgorythmId, const std::vector<uint8_t> &encryptedData);
private:
    PKCS7() : PKCSBase("", "") {}
};

}

#endif // PKCS7_H
