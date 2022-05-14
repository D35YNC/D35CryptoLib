#ifndef BASE64_H
#define BASE64_H

#include <string>
#include <vector>

namespace MyCryptoLib
{
    class Base64
{
public:
    static std::string b64Encode(const std::string &data)
    {
        return Base64::b64Encode(std::vector<uint8_t>(data.begin(), data.end()));
    }

    static std::string b64Encode(const std::vector<uint8_t> &data)
    {
        std::string result;

        // Работаем с блоками по 3 байта = 24 бита
        uint8_t block[3];
        int blockSize = 0;
        int i = 0;
        while (i < data.size())
        {
            block[i % 3] = data[i];
            i++;
            blockSize++;

            if (blockSize == 3)
            {
                uint32_t buffer = ((uint32_t)block[0] << 16) | ((uint32_t)block[1] << 8) | ((uint32_t)block[2]);

                for (int j = 3; j >= 0/*3 - blockSize*/; j--)
                {
                    result += Base64::base64Alphabet[(buffer >> (6 * j)) % 64];
                }

                blockSize = 0;
            }
        }

        if (blockSize > 0)
        {
            // Ну по идее можно и не дополнять нулями ну пусть будет
            for (int i = blockSize; i < 3; i++)
            {
                block[i] = 0;
            }
            uint32_t buffer = block[0] << 16 | block[1] << 8 | block[2];

            for (int i = 3; i >= 3 - blockSize; i--)
            {
                result += Base64::base64Alphabet[(buffer >> (6 * i)) % 64];
            }

            if (blockSize == 1)
            {
                result += "==";
            }
            else
            {
                result += "=";
            }
        }

        return result;
    };

    static std::vector<uint8_t> b64Decode(const std::string &data)
    {
        std::vector<uint8_t> result;

        int i = 0;
        int blockSize = 0;
        uint32_t block[4];

        while (i < data.size() && data[i] != '=' && Base64::isBase64Char(data[i]))
        {
            block[i % 4] = static_cast<uint8_t>(Base64::base64Alphabet.find(data[i]));
            i++;
            blockSize++;

            if (blockSize == 4)
            {
                // Использование промежуточного буфера мне кажется более более более
                // Кароче легче понять смысл сдвигов
                uint32_t buffer = (block[0] << 18) | (block[1] << 12) | (block[2] << 6) | (block[3]);

                for (int j = 2; j >= 0; j--)
                {
                    result.push_back(buffer >> (j * 8));
                }

                blockSize = 0;
            }
        }

        if (blockSize > 0)
        {
            for (int i = blockSize; i < 4; i++)
            {
                block[i] = 0;
            }

            uint32_t buffer = (block[0] << 18) | (block[1] << 12) | (block[2] << 6) | (block[3]);

            for (int j = 2; j >= blockSize - 2; j--)
            {
                result.push_back(buffer >> (j * 8));
            }
        }

        return result;
    }

private:
    Base64() { }

    static bool isBase64Char(char c)
    {
        return Base64::base64Alphabet.find(c) != std::string::npos || c == '=';
    }

    inline static const std::string base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
};
}

#endif // BASE64_H
