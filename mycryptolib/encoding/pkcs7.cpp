#include "pkcs7.h"


MyCryptoLib::PKCS7::PKCS7(const std::string &filename):
    PKCSBase("-----BEGIN PKCS7-----", "-----END PKCS7-----")
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
            fileBuffer[4] == 0x2d) // -----
    {
        std::string pemData(fileBuffer.begin(), fileBuffer.end());

        size_t pemTerminatorIndex = pemData.find(this->pemTerminator);
        if (pemTerminatorIndex == std::string::npos)
        {
            throw MyCryptoLib::BadPKCSFileStructureException("FUCK I CANT FIND PEM TERMINATOR");
        }                       // 22 == len(----BEGIN PKCS7----)               - pemHeader size потому что этот аргумент отвечает за количество символов
        //                                                                     и когда мы берем колво символов == индексу терминаторра
        //                                                                     То захватываем ненужные символы
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


MyCryptoLib::PKCS7::PKCS7(const std::map<int, std::vector<uint8_t> > &data) :
    PKCSBase("-----BEGIN PKCS7-----", "-----END PKCS7-----")
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


MyCryptoLib::PKCS7 MyCryptoLib::PKCS7::packEncryptedPKCS7(uint8_t version, const std::string &contentType, const std::string &encryptAlgorythmId, const std::vector<uint8_t> &encryptedData)
{
    std::map<int, std::vector<uint8_t>> dataMap;

    dataMap[0] = std::vector<uint8_t>(1, version);
    dataMap[1] = std::vector<uint8_t>(contentType.begin(), contentType.end());
    dataMap[2] = std::vector<uint8_t>(encryptAlgorythmId.begin(), encryptAlgorythmId.end());
    dataMap[3] = encryptedData;

    return PKCS7(dataMap);
}

std::vector<uint8_t> MyCryptoLib::PKCS7::getData() const
{
    return this->pkcsData.at(3);
}
