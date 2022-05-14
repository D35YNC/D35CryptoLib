#include "pkcs8.h"

MyCryptoLib::PKCS8::PKCS8(const std::string &keyAlgorithm, const std::map<int, std::vector<uint8_t>> &data) : IPKCS(), keyAlgorithm(keyAlgorithm)
{
    this->pkcsData = data;
}

MyCryptoLib::PKCS8::PKCS8(const std::string &filename) : IPKCS()
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

    this->pkcsData = dataMap;
}
