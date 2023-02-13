#pragma once

#include <vector>
#include <string>

#include <random>
#include <stdexcept> // for invalid_argument exception

#include "../hash/hmac.h"

#include "../utils.h"

namespace D35Crypto
{

class Key
{
public:
    Key(const std::vector<uint8_t> &keyBytes): bytes(keyBytes)
    {
        if (keyBytes.empty())
        {
            throw std::invalid_argument("Key shoudlldld be not empty pls");
        }
    }

    size_t size() const
    {
        return this->bytes.size();
    }

    std::vector<uint8_t> raw() const
    {
        return this->bytes;
    }

    std::string hex() const
    {
        return bytesToHexString(this->bytes);
    }

    static Key generate(size_t bitSize)
    {

        // CHECK MEMES PLS
        // https://vk.com/wall-207856611_49
        // =) =) =)

        if (bitSize % 8 != 0)
        {
            throw std::invalid_argument("Bad key size");
        }
        int bytesSize = static_cast<int>(bitSize / 8);

        std::uniform_int_distribution<uint8_t> dist(0, UINT8_MAX - 1);
        std::random_device dev_random("/dev/random"); // daaamn

        std::vector<uint8_t> bytes(bytesSize, 0x00);
        for (int i = 0; i < bytesSize; i++)
        {
            bytes[i] = dist(dev_random);
        }

        return Key(bytes);
    }

//    template<class T>
//    static Key pbkdf2(const std::string &passwd, int iterations = 4096, int length = 256, const std::vector<uint8_t> &salt = {})
//    {
//        std::vector<uint8_t> passwdBytes(passwd.begin(), passwd.end());
//        HMAC<T> hmac;

//        length /= 8;

//        int blocks_count = (length / hmac.digestSize()) + 1;

//        std::vector<uint8_t> result(blocks_count * hmac.digestSize(), 0x00);
//        size_t pos = 0;

//        std::vector<uint8_t> tmp;

//        for (int i = 1; i <= blocks_count; i++)
//        {
//            if (salt.size() > 0)
//            {
//                tmp.resize(salt.size() + 4);
//                std::copy(salt.begin(), salt.end(), tmp.begin());
//            }
//            else
//            {
//                tmp.resize(4);
//            }

//            tmp[tmp.size() - 1] = static_cast<uint8_t>(i      );
//            tmp[tmp.size() - 2] = static_cast<uint8_t>(i >> 8 );
//            tmp[tmp.size() - 3] = static_cast<uint8_t>(i >> 16);
//            tmp[tmp.size() - 4] = static_cast<uint8_t>(i >> 24);

//            hmac.create(tmp, passwdBytes);
//            tmp = hmac.digest();

//            for (int c = 1; c < iterations; c++)
//            {
//                hmac.create(tmp, passwdBytes);
//                tmp = xorBlocks(hmac.digest(), tmp);
//            }
//            std::copy(tmp.begin(), tmp.end(), result.begin() + pos);
//            pos += tmp.size();
//        }

//        result.resize(length);
//        return Key(result);
//    }

    uint8_t operator[](size_t index)
    {
        if (index < this->bytes.size())
        {
            return bytes[index];
        }
        throw std::out_of_range("Index out of range");
    }

protected:
    std::vector<uint8_t> bytes;
};

}
