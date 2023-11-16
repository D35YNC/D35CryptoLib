#ifndef BASE32_H
#define BASE32_H

#include <string>
#include <vector>

namespace D35Crypto
{
    class Base32
{
public:
    static std::string encode(const std::vector<uint8_t> &data)
    {
        std::string result;

        // Работаем с блоками по 5 байт = 40 бит
        uint8_t block[5] = { 0x00 };
        int blockSize = 0;
        int i = 0;
        while (i < data.size())
        {
            block[i % 5] = data[i];
            i++;
            blockSize++;

            if (blockSize == 5)
            {
                uint64_t buffer =
                        (static_cast<uint64_t>(block[0]) << 32) |
                        (static_cast<uint64_t>(block[1]) << 24) |
                        (static_cast<uint64_t>(block[2]) << 16) |
                        (static_cast<uint64_t>(block[3]) << 8 ) |
                        (static_cast<uint64_t>(block[4])      );

                for (int j = 7; j >= 0; j--)
                {
                    result += Base32::base32Alphabet[(buffer >> (5 * j)) % 32];
                }

                blockSize = 0;
            }
        }

        if (blockSize > 0)
        {
            for (int i = blockSize; i < 5; i++)
            {
                block[i] = 0;
            }
            uint64_t buffer =
                    (static_cast<uint64_t>(block[0]) << 32) |
                    (static_cast<uint64_t>(block[1]) << 24) |
                    (static_cast<uint64_t>(block[2]) << 16) |
                    (static_cast<uint64_t>(block[3]) << 8 ) |
                    (static_cast<uint64_t>(block[4])      );

            // ПОЧЕМУ 6 А НЕ 7 ПОЧЕМУ ПОЧЕМУ
            // потому что
            // Потому что нам не нужно зацепить следующий кусок блока кароче как это сказать
            // Ну а если так то мы его не цепляем вот
            for (int i = 7; i >= 0; i--)
            {
                result += Base32::base32Alphabet[(buffer >> (5 * i)) % 32];
            }

            // blockSize = 5 - (n % 5) //?no
            switch ((data.size() * 8) % 5)
            {
            case 1:
            {
                result += "====";
                break;
            }
            case 2:
            {
                result += "=";
                break;
            }
            case 3:
            {
                result += "======";
                break;
            }
            case 4:
            {
                result += "===";
                break;
            }
            }
        }

        return result;
    }

    static std::vector<uint8_t> decode(const std::string &data)
    {
        std::vector<uint8_t> result;

        int i = 0;
        int blockIndex = 0;
        int blockSize = 0;
        uint8_t block[8];

        while (i < data.size() && data[i] != '=')
        {
            // Skip non b32 symbols
            // TODO ADDoption
            if (!Base32::isBase32Char(data[i]))
            {
                i++;
                continue;
            }

            block[blockIndex % 8] = static_cast<uint8_t>(Base32::base32Alphabet.find(data[i]));
            i++;
            blockIndex++;
            blockSize++;

            if (blockSize == 8)
            {
                uint64_t buffer =
                        (static_cast<uint64_t>(block[0]) << 35) |
                        (static_cast<uint64_t>(block[1]) << 30) |
                        (static_cast<uint64_t>(block[2]) << 25) |
                        (static_cast<uint64_t>(block[3]) << 20) |
                        (static_cast<uint64_t>(block[4]) << 15) |
                        (static_cast<uint64_t>(block[5]) << 10) |
                        (static_cast<uint64_t>(block[6]) << 5 ) |
                        (static_cast<uint64_t>(block[7])      );

                for (int j = 4; j >= 0; j--)
                {
                    result.push_back(buffer >> (j * 8));
                }

                blockSize = 0;
            }
        }

        if (blockSize > 0)
        {
            for (int i = blockSize; i < 8; i++)
            {
                block[i] = 0;
            }


            uint64_t buffer =
                    (static_cast<uint64_t>(block[0]) << 35) |
                    (static_cast<uint64_t>(block[1]) << 30) |
                    (static_cast<uint64_t>(block[2]) << 25) |
                    (static_cast<uint64_t>(block[3]) << 20) |
                    (static_cast<uint64_t>(block[4]) << 15) |
                    (static_cast<uint64_t>(block[5]) << 10) |
                    (static_cast<uint64_t>(block[6]) << 5 ) |
                    (static_cast<uint64_t>(block[7])      );

            for (int j = 4; j >= blockSize - 4; j--)
            {
                result.push_back(buffer >> (j * 8));
            }
        }

        return result;
    }


private:
    Base32() { }

    static bool isBase32Char(char c)
    {
        return Base32::base32Alphabet.find(c) != std::string::npos || c == '=';
    }

    inline static const std::string base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
};
}

#endif // BASE32_H
