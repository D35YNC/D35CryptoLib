#pragma once

#include <string>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <vector>
#include <algorithm>

namespace D35Crypto
{
class HashBase
{
public:
    HashBase(int digestSize, std::string name) :
        _digest(digestSize, 0x00),
        _name(name)
    { }
    virtual ~HashBase() = default;
    virtual void update(const std::string &data) = 0;
    virtual void update(const std::vector<uint8_t> &data) = 0;
    virtual void update(std::ifstream& file) = 0;

    virtual size_t blockSize() = 0;

    std::string name() const
    {
        return this->_name;
    }

    std::vector<uint8_t> digest() const
    {
        return this->_digest;
    }

    std::string hexDigest() const
    {
        std::stringstream ss;
        ss << std::setfill('0') << std::hex;

        for (int i = 0; i < this->_digest.size(); i++)
        {
            ss << std::setw(2) << static_cast<unsigned int>(this->_digest[i]);
        }

        return ss.str();
    }

    size_t digestSize() const
    {
        return this->_digest.size();
    }

protected:
    std::vector<uint8_t> _digest;
    std::string _name;

    void _setNewDigestSize(int newSize)
    {
        newSize = (int)(newSize / 8);
        if (newSize > 0)
        {
            this->_digest.resize(newSize);
        }
    }
};
}

