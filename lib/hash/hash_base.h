#pragma once

#include <string>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <vector>
#include <algorithm>

#include "../utils.h"

namespace D35Crypto
{
class HashBase
{
public:
    HashBase(int digestSize) :
        _digest(digestSize, 0x00)
    { }
    virtual ~HashBase() = default;
    virtual void update(const std::string &data) = 0;
    virtual void update(const std::vector<uint8_t> &data) = 0;
    virtual void update(std::ifstream &file) = 0;

    virtual size_t blockSize() const noexcept = 0;
    virtual const std::string name() const noexcept = 0;

    std::vector<uint8_t> digest() const
    {
        return this->_digest;
    }

    std::string hexDigest() const
    {
        return bytesToHexString(this->digest());
    }

    size_t digestSize() const
    {
        return this->_digest.size();
    }

protected:
    std::vector<uint8_t> _digest;

};
}

