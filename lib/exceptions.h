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

class BadKeyfileStructureException: public std::runtime_error
{
public:
    BadKeyfileStructureException(const std::string &msg) : std::runtime_error(msg)
    { }
};

}
