#ifndef PKCS8_H
#define PKCS8_H

#include "ipkcs.h"

namespace MyCryptoLib
{
class PKCS8 : public IPKCS
{
public:
    PKCS8(const std::string &keyAlgorithm, const std::map<int, std::vector<uint8_t>> &data);
    PKCS8(const std::string &filename);

    std::vector<uint8_t> toPem()
    {
        return IPKCS::toPem(keyAlgorithm + keyType);
    }

private:
    PKCS8() : IPKCS() { }

    std::string keyAlgorithm;
    const std::string keyType = " PUBLIC KEY";
};
}

#endif // PKCS8_H
