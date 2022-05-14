#include "pkcs7.h"

MyCryptoLib::PKCS7::PKCS7(const std::map<int, std::vector<uint8_t> > &data) : IPKCS()
{
    if (data.size() > 0)
    {
        pkcsData = data;
    }
    else
    {
        throw std::invalid_argument("pkcs data is empty");
    }
}

MyCryptoLib::PKCS7::PKCS7(const std::string &filename)
{
    std::ifstream pkcsFile(filename);
    if (!pkcsFile.is_open())
    {
        throw std::runtime_error("Cant open file: " + filename);
    }

    pkcsFile.seekg(0, std::ios::end);
    size_t size = pkcsFile.tellg();
    pkcsFile.seekg(0, std::ios::beg);

    std::vector<uint8_t> fileBuffer(size, 0x00);
    pkcsFile.read((char*)fileBuffer.data(), size);

    std::map<int, std::vector<uint8_t>> dataMap;
    size_t pos = 0;
    size_t fieldSizie = 0;
    std::vector<uint8_t> fieldBuffer;
    while (pos < size)
    {
        // INCREMENT ALERT
        fieldSizie |= fileBuffer[pos++] << 8;
        fieldSizie |= fileBuffer[pos++];

        if (!(0 < fieldSizie && fieldSizie < 65536)) // Просто ограничение на всякий случай
        {
            throw std::runtime_error("bad field size, cant read");
        }

        fieldBuffer.resize(fieldSizie);
        std::copy(fileBuffer.begin() + pos, fileBuffer.begin() + pos + fieldSizie, fieldBuffer.begin());
        dataMap[dataMap.size()] = fieldBuffer;
    }
}

MyCryptoLib::PKCS7 MyCryptoLib::PKCS7::packEncryptedPKCS7(uint8_t version, const std::string &contentType, const std::string &encryptAlgorythmId, const std::vector<uint8_t> &encryptedData)
{
    std::map<int, std::vector<uint8_t>> dataMap;

    dataMap[0] = std::vector<uint8_t>(1, version);
    dataMap[1] = std::vector<uint8_t>(contentType.begin(), contentType.end());
    dataMap[2] = std::vector<uint8_t>(encryptAlgorythmId.begin(), encryptAlgorythmId.end());
    dataMap[3] = encryptedData;

    return PKCS7(dataMap);
}

std::vector<uint8_t> MyCryptoLib::PKCS7::getData()
{
    return this->pkcsData.at(3);
}
