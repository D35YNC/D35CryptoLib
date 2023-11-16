#ifndef HMAC_H
#define HMAC_H

#include <vector>
#include <string>
#include <algorithm>
#include <type_traits>

#include "hash_base.h"
#include "../utils.h"
#include "../exceptions.h"


namespace D35Crypto
{

template <class T>
class HMAC
{
public:
    HMAC()
    {
        static_assert(std::is_base_of_v<HashBase, T>, "HMAC: it is necessary that the hash function class inherits from D35Crypto::HashBase");
        this->__hash = new T();
    }

    ~HMAC()
    {
        delete this->__hash;
    }

    void create(const std::string& data, const std::vector<uint8_t>& key)
    {
        this->create(std::vector<uint8_t>(data.begin(), data.end()), key);
    }

    void create(const std::vector<uint8_t>& data, const std::vector<uint8_t> &key)
    {
        std::vector<uint8_t> key_0(key.begin(), key.end());

        if (key.size() > this->__hash->blockSize())
        {
            this->__hash->update(key_0);
            key_0 = this->__hash->digest();
        }
        else if (key.size() < this->__hash->blockSize())
        {
            key_0.resize(this->__hash->blockSize(), 0x00);
        }

        std::vector<uint8_t> ipad((int)(this->__hash->blockSize()), 0x36); // 00110110
        std::vector<uint8_t> opad((int)(this->__hash->blockSize()), 0x5c); // 01011100

        // step 1
        // XOR ALL XORING
        for (int i = 0; i < this->__hash->blockSize(); i++)
        {
            ipad[i] ^= key_0[i];
            opad[i] ^= key_0[i];
        }

        // Step 2 H((IPAD ^ KEY) + DATA)
        std::vector<uint8_t> tmp_rigth_part(ipad.size() + data.size());
        std::copy(ipad.begin(), ipad.end(), tmp_rigth_part.begin());
        std::copy(data.begin(), data.end(), tmp_rigth_part.begin() + ipad.size());
        this->__hash->update(tmp_rigth_part);
        tmp_rigth_part = this->__hash->digest();

        // Step 3 H((OPAD^KEY) + STEP2)
        opad.resize(opad.size() + tmp_rigth_part.size());
        std::copy(tmp_rigth_part.begin(), tmp_rigth_part.end(), opad.begin() + (opad.size() - tmp_rigth_part.size()));
        this->__hash->update(opad);
        // YEAHS
        this->__hmac = this->__hash->digest();
    }

    std::vector<uint8_t> digest()
    {
        return this->__hmac;
    }

    std::string hexDigest()
    {
        return bytesToHexString(this->__hmac);
    }

    size_t digestSize()
    {
        return this->__hash->digestSize();
    }

    std::string name()
    {
        return "HMAC-" + this->__hash->name();
    }

private:
    T* __hash;
    std::vector<uint8_t> __hmac;
};

}

#endif // HMAC_H
