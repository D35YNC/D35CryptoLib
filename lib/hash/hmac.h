#ifndef HMAC_H
#define HMAC_H

#include <vector>
#include <string>
#include <algorithm>
#include <type_traits>

#include "hash_base.h"
#include "../exceptions.h"
#include "../symmetric_key/key.h"


namespace D35Crypto
{
template <class T>
class HMAC
{
public:
    HMAC()
    {
        if (!std::is_base_of_v<HashBase, T>)
        {
            throw D35Crypto::ItsNotHashException("it is necessary that the hash function class inherits from D35Crypto::HashBase");
        }
        this->hash = new T();
    }

    ~HMAC()
    {
        delete this->hash;
    }

    void create(const std::string& data, const Key& key)
    {
        this->create(std::vector<uint8_t>(data.begin(), data.end()), key);
    }

    void create(const std::vector<uint8_t>& data, const Key& key)
    {
        std::vector<uint8_t> key_0 = key.raw();

        if (key.size() > this->hash->blockSize())
        {
            this->hash->update(key_0);
            key_0 = this->hash->digest();
        }
        else if (key.size() < this->hash->blockSize())
        {
            key_0.resize(this->hash->blockSize(), 0x00);
        }

        std::vector<uint8_t> ipad((int)(this->hash->blockSize()), 0x36); // 00110110
        std::vector<uint8_t> opad((int)(this->hash->blockSize()), 0x5c); // 01011100

        // step 1
        // XOR ALL XORING
        for (int i = 0; i < this->hash->blockSize(); i++)
        {
            ipad[i] ^= key_0[i];
            opad[i] ^= key_0[i];
        }

        // Step 2 H((IPAD ^ KEY) + DATA)
        std::vector<uint8_t> tmp_rigth_part(ipad.size() + data.size());
        std::copy(ipad.begin(), ipad.end(), tmp_rigth_part.begin());
        std::copy(data.begin(), data.end(), tmp_rigth_part.begin() + ipad.size());
        this->hash->update(tmp_rigth_part);
        tmp_rigth_part = this->hash->digest();

        // Step 3 H((OPAD^KEY) + STEP2)
        opad.resize(opad.size() + tmp_rigth_part.size());
        std::copy(tmp_rigth_part.begin(), tmp_rigth_part.end(), opad.begin() + (opad.size() - tmp_rigth_part.size()));
        this->hash->update(opad);
        // YEAHS
        this->hmac = this->hash->digest();
    }

    std::vector<uint8_t> raw()
    {
        return this->hmac;
    }

    std::string hex()
    {
        std::stringstream ss;
        ss << std::setfill('0') << std::hex;

        for (int i = 0; i < this->hmac.size(); i++)
        {
            ss << std::setw(2) << (unsigned int)(this->hmac[i]);
        }

        return ss.str();
    }

    std::string name()
    {
        return "HMAC-" + this->hash->name();
    }

private:
    T* hash;
    std::vector<uint8_t> hmac;
};
}

#endif // HMAC_H