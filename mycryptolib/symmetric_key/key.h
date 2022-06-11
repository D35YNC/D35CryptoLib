#pragma once

#include <vector>
#include <string>
#include <sstream> // |
#include <iomanip> // +- for std::string rawString(){...}
#include <random>
#include <stdexcept> // for invalid_argument exception

#include "../encoding/base64.h"

namespace MyCryptoLib
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

    Key(const std::initializer_list<uint8_t> &keyBytes): bytes(keyBytes)
    {
        if (keyBytes.size() == 0)
        {
            throw std::invalid_argument("Key shoudlldld be not empty pls");
        }
    }

    size_t size() const
    {
        return this->bytes.size();
    }

    std::string b64() const
    {
        return MyCryptoLib::Base64::b64Encode(this->bytes);
    }

    std::vector<uint8_t> raw() const
    {
        return this->bytes;
    }

    std::string rawString() const
    {
        std::stringstream ss;
        ss << std::setfill('0') << std::hex;

        for (int i = 0; i < this->bytes.size(); i++)
        {
            ss << std::setw(2) << static_cast<unsigned int>(this->bytes[i]);
        }

        return ss.str();
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
        int bytesSize = (int)(bitSize / 8);

        std::uniform_int_distribution<uint8_t> dist(0, UINT8_MAX - 1);
        std::random_device dev_random("/dev/random");

        std::vector<uint8_t> bytes(bytesSize, 0x00);
        for (int i = 0; i < bytesSize; i++)
        {
            bytes[i] = dist(dev_random);
        }

        return Key(bytes);
    }

protected:
    std::vector<uint8_t> bytes;
};

}
