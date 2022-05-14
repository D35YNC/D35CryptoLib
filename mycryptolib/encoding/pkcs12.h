#ifndef PKCS12_H
#define PKCS12_H

#include "ipkcs.h"

namespace MyCryptoLib
{
class PKCS12 : public IPKCS
{
public:
    PKCS12(const std::string &keyAlgorythm, const std::map<int, std::vector<uint8_t>> &data);
    PKCS12(const std::string &filename);

    std::vector<uint8_t> toPem()
    {
        return IPKCS::toPem(keyAlgorithm + keyType);
    }

private:
    PKCS12() : IPKCS() { }

    std::string keyAlgorithm;
    const std::string keyType = " PRIVATE KEY";
};
}

#endif // PKCS12_H
