#include "pkcs7.h"


MyCryptoLib::PKCS7::PKCS7(const std::string &filename):
    PKCSBase("-----BEGIN PKCS7 ENCRYPTED DATA-----", "-----END PKCS7 ENCRYPTED DATA-----")
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
            // maybe its sign?
            throw MyCryptoLib::BadPKCSFileStructureException("FUCK I CANT FIND PEM TERMINATOR");
        }
        pemData = pemData.substr(this->pemHeader.size() + 1, pemTerminatorIndex - this->pemHeader.size() - 1);
        fileBuffer = MyCryptoLib::Base64::b64Decode(pemData);
    }

    size_t pos = 0;
    size_t fieldSize = 0;
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

        dataMap[dataMap.size()] = std::vector<uint8_t>(fileBuffer.begin() + pos, fileBuffer.begin() + pos + fieldSize);
        pos += fieldSize;
        fieldSize = 0;
    }

    this->pkcsData = dataMap;
}


MyCryptoLib::PKCS7::PKCS7(const std::map<int, std::vector<uint8_t> > &data) :
    PKCSBase("-----BEGIN PKCS7 ENCRYPTED DATA-----", "-----END PKCS7 ENCRYPTED DATA-----")
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


MyCryptoLib::PKCS7 MyCryptoLib::PKCS7::fromFile(const std::string &filename)
{
    std::ifstream pkcsFile(filename);
    if (!pkcsFile.is_open())
    {
        throw std::runtime_error("Cant open file: " + filename);
    }

    std::string pemHeader = "-----BEGIN PKCS7 ENCRYPTED DATA-----";
    std::string pemTerminator = "-----END PKCS7 ENCRYPTED DATA-----";

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

        size_t pemTerminatorIndex = pemData.find(pemTerminator);
        if (pemTerminatorIndex == std::string::npos)
        {
            throw MyCryptoLib::BadPKCSFileStructureException("FUCK I CANT FIND PEM TERMINATOR");
        }
        pemData = pemData.substr(pemHeader.size() + 1, pemTerminatorIndex - pemHeader.size() - 1);
        fileBuffer = MyCryptoLib::Base64::b64Decode(pemData);
    }

    size_t pos = 0;
    size_t fieldSize = 0;
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

        dataMap[dataMap.size()] = std::vector<uint8_t>(fileBuffer.begin() + pos, fileBuffer.begin() + pos + fieldSize);
        pos += fieldSize;
        fieldSize = 0;
    }
    return PKCS7(dataMap);
}


//MyCryptoLib::PKCS7Data MyCryptoLib::PKCS7Data::fromFile(const std::string &filename)
//{
//    std::ifstream pkcsFile(filename, std::ios::binary);
//    if (!pkcsFile.is_open())
//    {
//        throw std::runtime_error("Cant open file: " + filename);
//    }

//    std::string pemHeader = "-----BEGIN PKCS7 ENCRYPTED DATA-----";
//    std::string pemTerminator = "-----END PKCS7 ENCRYPTED DATA-----";


//    pkcsFile.seekg(0, std::ios::end);
//    size_t completeSize = pkcsFile.tellg();
//    pkcsFile.seekg(0, std::ios::beg);

//    size_t headerPos = 0;
//    size_t terminatorPos = 0;

//    size_t pos = 0;
//    std::vector<uint8_t> fileBuffer(1024, 0x00);

//    while (pos < completeSize)
//    {
//        pkcsFile.read(reinterpret_cast<char*>(fileBuffer.data()), fileBuffer.size());
//        std::string marker(fileBuffer.begin(), fileBuffer.end());

//        headerPos = marker.find(pemHeader);
//        if (headerPos != std::string::npos)
//        {
//            break;
//        }
//        pos += 1024;
//    }

//    if (headerPos != std::string::npos)
//    {
//        pos = 0;
//        pkcsFile.seekg(headerPos, std::ios::beg);

//        while (pos < completeSize)
//        {
//            pkcsFile.read(reinterpret_cast<char*>(fileBuffer.data()), fileBuffer.size());
//            std::string marker(fileBuffer.begin(), fileBuffer.end());

//            terminatorPos = marker.find(pemTerminator);
//            if (terminatorPos != std::string::npos)
//            {
//                break;
//            }
//            pos += 1024;
//        }
//    }



//    if (fileBuffer[0] == fileBuffer[1] &&
//            fileBuffer[1] == fileBuffer[2] &&
//            fileBuffer[2] == fileBuffer[3] &&
//            fileBuffer[3] == fileBuffer[4] &&
//            fileBuffer[4] == 0x2d)
//    {
//        // допустим в начале файла видим что то похожее на заголовок
//        // раз это начало то скорее всего это шифрованные данные
//        // Проверим
//        std::string marker(fileBuffer.begin(), fileBuffer.begin() + pemHeader.size());
//        if (marker != pemHeader)
//        {
//            throw MyCryptoLib::BadPKCSFileStructureException("File: " + filename + " is corrupted");
//        }
//    }

//    // auto iter = std::find(avArgs.begin(), avArgs.end(), args[i]);
//    // int index = iter - avArgs.begin();

//}


MyCryptoLib::PKCS7 MyCryptoLib::PKCS7::create(uint8_t version, const std::string &contentType, const std::string &encryptAlgorithmId, const std::vector<uint8_t> &encryptedData)
{
    std::map<int, std::vector<uint8_t>> dataMap;

    dataMap[0] = std::vector<uint8_t>(1, version);
    dataMap[1] = std::vector<uint8_t>(contentType.begin(), contentType.end());
    dataMap[2] = std::vector<uint8_t>(encryptAlgorithmId.begin(), encryptAlgorithmId.end());
    dataMap[3] = encryptedData;

    return PKCS7(dataMap);
}


std::vector<uint8_t> MyCryptoLib::PKCS7::getData() const
{
//    return this->pkcsData.at(3);
    return this->pkcsData.at(this->pkcsData.size() - 1);
}

