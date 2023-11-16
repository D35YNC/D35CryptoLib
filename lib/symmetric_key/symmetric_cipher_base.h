#pragma once

#include <string>
#include <fstream>
#include <vector>

#include "key.h"

namespace D35Crypto
{
enum CipherMode
{
    CBC,
    РСВС,
    CFB,
    OFB,
    CTR,
    GCM,
    NONE,
};

class SymmetricCipherBase
{
public:
    SymmetricCipherBase(const D35Crypto::Key &key, CipherMode mode) : __key(key), __mode(mode) { }
    virtual ~SymmetricCipherBase() = default;

    virtual std::vector<uint8_t> encrypt(const std::vector<uint8_t> &buffer) = 0;
    virtual std::vector<uint8_t> decrypt(const std::vector<uint8_t> &buffer) = 0;
    virtual void encrypt(std::ifstream &infile, std::ofstream &outfile) = 0;

    virtual size_t blockSize() const noexcept = 0;
    virtual const std::string name() const noexcept = 0;

protected:
    Key __key;
    CipherMode __mode;
};
}

