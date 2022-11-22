#pragma once


#include <string>
//#include <iomanip>
//#include <sstream>
//#include <fstream>
#include <vector>
//#include <algorithm>

#include "key.h"

namespace D35Crypto
{
class SymmetricCipherBase
{
public:
    SymmetricCipherBase(const std::string &cipherName, const Key &key) :
        cipherName(cipherName),
        key(key)
    { }
    virtual ~SymmetricCipherBase() = default;
//    virtual void encrypt(const std::string &buffer) = 0;
//    virtual void encrypt(std::ifstream& file) = 0;
    virtual std::vector<uint8_t> encrypt(const std::vector<uint8_t> &buffer) = 0;
    virtual std::vector<uint8_t> decrypt(const std::vector<uint8_t> &buffer) = 0;

    virtual size_t blockSize() = 0;

    std::string name() const
    {
        return this->cipherName;
    }


protected:
    std::string cipherName;
    Key key;
};
}

