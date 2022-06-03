#include "pkcs12.h"
#include<iomanip>

MyCryptoLib::PKCS12::PKCS12(const std::string &keyAlgorithm, const std::map<int, std::vector<uint8_t> > &data) :
    PKCSBase("-----BEGIN " + keyAlgorithm + " PRIVATE KEY-----", "-----END " + keyAlgorithm + " PRIVATE KEY-----"), keyAlgorithm(keyAlgorithm)
{
    this->pkcsData = data;
}

MyCryptoLib::PKCS12::PKCS12(const std::string &filename) : PKCSBase("", "")
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
    pkcsFile.read(reinterpret_cast<char*>(fileBuffer.data()), size);

    if (fileBuffer[0] == fileBuffer[1] &&
            fileBuffer[1] == fileBuffer[2] &&
            fileBuffer[2] == fileBuffer[3] &&
            fileBuffer[3] == fileBuffer[4] &&
            fileBuffer[4] == 0x2d) // "-----"
    {
        std::string pemData(fileBuffer.begin(), fileBuffer.end());

        // 11 = len "-----BEGIN "
        this->keyAlgorithm = pemData.substr(11, pemData.find(" PRIVATE KEY-----\n") - 11);
        this->pemHeader = "-----BEGIN " + this->keyAlgorithm + " PRIVATE KEY-----";
        this->pemTerminator = "-----END " + this->keyAlgorithm + " PRIVATE KEY-----";

        size_t pemTerminatorIndex = pemData.find(this->pemTerminator);
        if (pemTerminatorIndex == std::string::npos)
        {
            throw MyCryptoLib::BadPKCSFileStructureException("FUCK I CANT FIND PEM TERMINATOR");
        }
        pemData = pemData.substr(this->pemHeader.size() + 1, pemTerminatorIndex - this->pemHeader.size() - 1);
        fileBuffer = MyCryptoLib::Base64::b64Decode(pemData);
    }

    size_t pos = 0;
    size_t fieldSize = 0;
//    std::vector<uint8_t> fieldBuffer;
    std::map<int, std::vector<uint8_t>> dataMap;
    while (pos < fileBuffer.size())
    {
        // INCREMENT ALERT
        fieldSize |= (fileBuffer[pos++] << 8);
        fieldSize |= fileBuffer[pos++];

        if (!(0 < fieldSize && fieldSize < 65536)) // Просто ограничение на всякий случай
        {
            throw std::runtime_error("bad field size, cant read");
        }

//        fieldBuffer.resize(fieldSize);
//        std::copy(fileBuffer.begin() + pos, fileBuffer.begin() + pos + fieldSize, fieldBuffer.begin());
//        dataMap[dataMap.size()] = fieldBuffer;
        dataMap[dataMap.size()] = std::vector<uint8_t>(fileBuffer.begin() + pos, fileBuffer.begin() + pos + fieldSize);
        pos += fieldSize;
        fieldSize = 0;
    }

    this->pkcsData = dataMap;
}
