#ifndef PKCS12_H
#define PKCS12_H

#include "pkcs_base.h"
#include "../exceptions.h"

namespace D35Crypto
{
class PKCS12 : public PKCSBase
{
public:
    PKCS12(const std::string &filename);
    PKCS12(const std::string &keyAlgorythm, const std::map<int, std::vector<uint8_t>> &data);

private:
    PKCS12() : PKCSBase("", "") { }

    std::string keyAlgorithm;
};
}

#endif // PKCS12_H
