#ifndef HMAC_H
#define HMAC_H

#include "ihash.h"
#include "../symmetric_key/key.h"

#include "sha256.h"
#include "sha512.h"
#include "streebog.h"

#include <vector>
#include <string>

namespace MyCryptoLib
{
// Usin "Strategy" pattern =)
class HMAC
{
public:
    HMAC(IHash*);

    void setHash(IHash*);

    void create(const std::string&, const Key&);
    void create(const std::vector<uint8_t>&, const Key&);

    std::vector<uint8_t> raw();
    std::string hex();

    std::string name();
private:
    IHash* hash;
    std::vector<uint8_t> hmac;

    std::vector<uint8_t> xorBlocks(const std::vector<uint8_t>&, const std::vector<uint8_t>&, int);
};
}

#endif // HMAC_H
