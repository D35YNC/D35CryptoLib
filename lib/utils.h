#pragma once

#include <string>
#include <vector>
#include <sstream> // |
#include <iomanip> // +- for std::string rawString(){...}

namespace D35Crypto
{
static std::vector<uint8_t> xorBlocks(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b)
{
    if (a.size() != b.size())
    {
        throw std::logic_error("Cant xor blocks not equeal sizes");
        return {};
    }
    std::vector<uint8_t> result(a.size(), 0x00);
    for (int i = 0; i < a.size(); i++)
    {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

static std::string bytesToHexString(const std::vector<uint8_t> &bytes)
{
    std::stringstream ss;
    ss << std::setfill('0') << std::hex;

    for (int i = 0; i < bytes.size(); i++)
    {
        ss << std::setw(2) << static_cast<unsigned int>(bytes[i]);
    }

    return ss.str();
}

}
