#ifndef IPKCS_H
#define IPKCS_H

#include <map>
#include <vector>
#include <string>
#include <sstream>
#include <fstream>

#include "base64.h"

namespace MyCryptoLib
{
class IPKCS
{
public:
    std::vector<uint8_t> getField(int __index) const
    {
        if (0 <= __index && __index < pkcsData.size())
        {
            return pkcsData.at(__index);
        }
        else
        {
            throw std::runtime_error("INDEX ERROR");
        }
    }

    std::vector<uint8_t> toBytes()
    {
        size_t size = 0;
        for (const std::pair<int, std::vector<uint8_t>> &pair : pkcsData)
        {
            size += pair.second.size() + 2;
        }

        std::vector<uint8_t> result(size, 0x00);
        size_t pos = 0;

        for (int i = 0; i < pkcsData.size(); i++)
        {
            std::vector<uint8_t> buffer = pkcsData.at(i);
            size_t bufferSize = buffer.size();

            // INCREMENT ALERT
            // 0
            result[pos++] = bufferSize >> 8; // 0
            result[pos++] = bufferSize; // 1
            // 2
            std::copy(buffer.begin(), buffer.end(), result.begin() + pos);
            pos += bufferSize;
        }

        return result;
    }

protected:
    IPKCS() { }

    std::vector<uint8_t> toPem(std::string pemId)
    {
        std::stringstream ss;

        std::string b64string = Base64::b64Encode(this->toBytes());

        ss << "-----BEGIN " << pemId << "-----" << '\n';

        // wrap
        for (int i = 0; i < b64string.size(); i++)
        {
            ss << b64string[i];
            if (i % 80 == 0 && i != 0)
            {
                ss << '\n';
            }
        }

        ss << '\n' << "-----END " << pemId << "-----" << "\n";

        std::vector<uint8_t> result(ss.str().size());

        std::copy(ss.str().begin(), ss.str().end(), result.begin());
        return result;
    }

    std::map<int, std::vector<uint8_t>> pkcsData;

};
}


#endif // IPKCS_H
