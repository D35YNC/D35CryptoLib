#ifndef PKCS8_H
#define PKCS8_H

#include "pkcs_base.h"
#include "../exceptions.h"

namespace D35Crypto
{
class PKCS8 : public PKCSBase
{
public:
    PKCS8(const std::string &filename);
    PKCS8(const std::string &keyAlgorithm, const std::map<int, std::vector<uint8_t>> &data);

private:
    PKCS8() : PKCSBase("", "") { }

    std::string keyAlgorithm;
};
}

#endif // PKCS8_H
