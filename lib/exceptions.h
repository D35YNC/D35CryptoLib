#pragma once

#include <stdexcept>
#include <sstream>

namespace D35Crypto
{

class BaseException : public std::exception
{
public:
    virtual const std::string type() const noexcept = 0;

    const char* what() const noexcept override
    {
        if (this->_whatString.empty())
        {
            std::ostringstream oss;
            oss << this->type() << ": " << originString();
            this->_whatString = oss.str();
        }

        return this->_whatString.c_str();
    }

    int line() const noexcept
    {
        return this->__line;
    }

    const std::string& file() const noexcept
    {
        return this->__file;
    }

    std::string originString() const noexcept
    {
        std::ostringstream oss;
        oss << "[File] " << this->__file << "; "
            << "[Line] " << this->__line << "; "
            << "[Message] " << this->__message;

        return oss.str();
    }


protected:
    BaseException(int line, const std::string& file, const std::string &msg) noexcept
        :
          std::exception(),
          __line(line),
          __file(file),
          __message(msg)
    { }

    mutable std::string _whatString;

private:
    int         __line;
    std::string __file;
    std::string __message;
};

class KeyException : public BaseException
{
public:
    KeyException(int line, const std::string& file, const std::string &msg) noexcept  : BaseException(line, file, msg) { }
    const std::string type() const noexcept override { return "FileNotFoundException"; }
};

//
// Неверный размер ключа
// Бросаеттся когда размер ключа не соответствует "некоторым параметрам"
//
class BadKeySizeException : public KeyException
{
public:
    BadKeySizeException(int line, const std::string &file) noexcept : KeyException(line, file, "Bad key size") { }
    const std::string type() const noexcept override { return "BadKeySizeException"; }
};

//
// Неверный "тип" ключа
// Бросается когда путаются публичные/приватные ключи
//
class WrongKeyException : public KeyException
{
public:
    WrongKeyException(int line, const std::string &file, const std::string &msg) noexcept : KeyException(line, file, msg) { }
    const std::string type() const noexcept override { return "WrongKeyException"; }
};

}
