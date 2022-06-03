#ifndef HMAC_H
#define HMAC_H

#include "hash_base.h"
#include "../symmetric_key/key.h"

#include "sha256.h"
#include "sha512.h"
#include "streebog.h"

#include <vector>
#include <string>

namespace MyCryptoLib
{
class HMAC
{
public:
    HMAC(HashBase* hmacHash);

    void setHash(HashBase* hmacHash);

    void create(const std::string& data, const Key& key);
    void create(const std::vector<uint8_t>& data, const Key& key);

    std::vector<uint8_t> raw();
    std::string hex();

    std::string name();
private:
    HashBase* hash; // Usin "Strategy" pattern =)
    std::vector<uint8_t> hmac;

    std::vector<uint8_t> xorBlocks(const std::vector<uint8_t>&, const std::vector<uint8_t>&);
};
}

#endif // HMAC_H
