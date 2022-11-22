#pragma once

#include <vector>
#include <string>

namespace D35Crypto
{

class CRC32
{

public:
    static uint32_t calculate(const std::vector<uint8_t> &data, uint32_t crc = 0)
    {
        // https://stackoverflow.com/questions/27939882/fast-crc-algorithm
        crc = ~crc;

        for (int i = 0; i < data.size(); i++)
        {
            crc ^= data[i];
            for (int k = 0; k < 8; k++)
            {
                crc = crc & 1 ? (crc >> 1) ^ CRC32::POLYNOME : crc >> 1;
            }
        }
        return ~crc;
    }

private:
    /* CRC-32C (iSCSI) polynomial in reversed bit order. */
    // static const uint32_t POLYNOME = 0x82f63b78;

    /* CRC-32 (Ethernet, ZIP, etc.) polynomial in reversed bit order. */
    static const uint32_t POLYNOME = 0xedb88320;
};

}
