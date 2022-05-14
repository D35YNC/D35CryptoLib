#pragma once

#include <stdexcept>

namespace MyCryptoLib
{
class WrongKeyException: public std::runtime_error
{
public:
    WrongKeyException(const std::string &msg): std::runtime_error(msg)
    { }
};
class CorruptedSignatureException: public std::runtime_error
{
public:
    CorruptedSignatureException(const std::string &msg): std::runtime_error(msg)
    { }
};

class BadPKCSFileStructureException : public std::runtime_error
{
public:
    BadPKCSFileStructureException(const std::string &msg) : std::runtime_error(msg)
    { }
};
}

