#pragma once

#include <stdexcept>

namespace D35Crypto
{
class WrongKeyException: public std::runtime_error
{
public:
    WrongKeyException(const std::string &msg): std::runtime_error(msg)
    { }
};

class BadPKCSFileStructureException: public std::runtime_error
{
public:
    BadPKCSFileStructureException(const std::string &msg) : std::runtime_error(msg)
    { }
};

class ItsNotHashException: public std::runtime_error
{
public:
    ItsNotHashException(const std::string &msg) : std::runtime_error(msg)
    { }
};

}
