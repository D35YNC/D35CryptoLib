#include "cades.h"


MyCryptoLib::CAdES::CAdES(const std::map<int, std::vector<uint8_t>> &signData):
    signData(signData), caSignData({})
{
    if (signData.empty())
    {
        throw std::invalid_argument("cades data is empty");
    }
    if (signData.size() != 8)
    {
        throw std::invalid_argument("cades data broken");
    }
}

MyCryptoLib::CAdES MyCryptoLib::CAdES::create(uint8_t version, const std::string &contentType, const std::string &signerId, const std::vector<uint8_t> &signerPubKeyHash,
                                              const std::string &hashingAlgorithmId, const std::string &signingAlgorithmId, const std::vector<uint8_t> &contentHash,
                                              const std::vector<uint8_t> &signature)
{
    std::map<int, std::vector<uint8_t>> dataMap;

    dataMap[0] = std::vector<uint8_t>(1, version);
    dataMap[1] = std::vector<uint8_t>(contentType.begin(),          contentType.end());
    dataMap[2] = std::vector<uint8_t>(contentHash.begin(),          contentHash.end());
    dataMap[3] = std::vector<uint8_t>(signerId.begin(),             signerId.end());
    dataMap[4] = std::vector<uint8_t>(signerPubKeyHash.begin(),     signerPubKeyHash.end());
    dataMap[5] = std::vector<uint8_t>(hashingAlgorithmId.begin(),   hashingAlgorithmId.end());
    dataMap[6] = std::vector<uint8_t>(signingAlgorithmId.begin(),   signingAlgorithmId.end());
    dataMap[7] = std::vector<uint8_t>(signature.begin(),            signature.end());

    return CAdES(dataMap);
}

MyCryptoLib::CAdES MyCryptoLib::CAdES::fromBytes(const std::vector<uint8_t> &buffer)
{
    size_t userSignHeaderPos = std::string::npos;
    size_t userSignTerminatorPos = std::string::npos;
    size_t caSignHeaderPos = std::string::npos;
    size_t caSignTerminatorPos = std::string::npos;
    size_t pos = 0;

    while (pos < buffer.size())
    {
        std::string marker(buffer.begin() + pos, buffer.begin() + pos + 1024);

        if (userSignHeaderPos == std::string::npos)
        {
            userSignHeaderPos = marker.find(CAdES::userSignHeader);
            if (userSignHeaderPos != std::string::npos)
            {
                userSignHeaderPos += pos;
            }
        }
        if (userSignTerminatorPos == std::string::npos)
        {
            userSignTerminatorPos = marker.find(CAdES::userSignTerminator);
            if (userSignTerminatorPos != std::string::npos)
            {
                userSignTerminatorPos += pos;
            }
        }
        if (caSignHeaderPos == std::string::npos)
        {
            caSignHeaderPos = marker.find(CAdES::caSignHeader);
            if (caSignHeaderPos != std::string::npos)
            {
                caSignHeaderPos += pos;
            }
        }
        if (caSignTerminatorPos == std::string::npos)
        {
            caSignTerminatorPos = marker.find(CAdES::caSignTerminator);
            if (caSignTerminatorPos != std::string::npos)
            {
                caSignTerminatorPos += pos;
            }
        }

        pos += 512;
    }

    if (userSignHeaderPos == std::string::npos)
    {
        throw MyCryptoLib::BadPKCSFileStructureException("Cant find pkcs sign header");
    }
    if (userSignTerminatorPos == std::string::npos)
    {
        throw MyCryptoLib::BadPKCSFileStructureException("Cant find pkcs sign terminator");
    }
    if (userSignHeaderPos > userSignTerminatorPos)
    {
        throw MyCryptoLib::BadPKCSFileStructureException("Confusing pkcs structure, cant read");
    }

    std::vector<uint8_t> caSignBuffer;
    std::vector<uint8_t> userSignBuffer(buffer.begin() + userSignHeaderPos + CAdES::userSignHeader.size(), buffer.begin() + userSignTerminatorPos);
    if (caSignHeaderPos != caSignTerminatorPos && caSignHeaderPos != std::string::npos && caSignTerminatorPos != std::string::npos)
    {
        caSignBuffer = std::vector<uint8_t>(buffer.begin() + caSignHeaderPos + CAdES::caSignHeader.size(), buffer.begin() + caSignTerminatorPos);
        MyCryptoLib::CAdES cades = MyCryptoLib::CAdES::parseBuffers(userSignBuffer, caSignBuffer);
        cades.userSignHeaderPos = userSignHeaderPos;
        cades.userSignTerminatorPos = userSignTerminatorPos;
        cades.caSignHeaderPos = caSignHeaderPos;
        cades.caSignTerminatorPos = caSignTerminatorPos;
        return cades;
    }
    MyCryptoLib::CAdES cades = MyCryptoLib::CAdES::parseBuffers(userSignBuffer);
    cades.userSignHeaderPos = userSignHeaderPos;
    cades.userSignTerminatorPos = userSignTerminatorPos;
    cades.caSignHeaderPos = caSignHeaderPos;
    cades.caSignTerminatorPos = caSignTerminatorPos;
    return cades;
}


MyCryptoLib::CAdES MyCryptoLib::CAdES::parseBuffers(const std::vector<uint8_t> &userSign, const std::vector<uint8_t> &caSign)
{
    size_t pos = 0;
    size_t fieldSize = 0;
    std::map<int, std::vector<uint8_t>> signMap;

    while (pos < userSign.size())
    {
        // INCREMENT ALERT
        fieldSize |= (userSign[pos++] << 8);
        fieldSize |= (userSign[pos++]     );

        if (!(0 < fieldSize && fieldSize < 65536)) // Просто ограничение на всякий случай
        {
            throw std::runtime_error("bad field size, cant read");
        }

        signMap[signMap.size()] = std::vector<uint8_t>(userSign.begin() + pos, userSign.begin() + pos + fieldSize);
        pos += fieldSize;
        fieldSize = 0;
    }

    if (signMap.size() != 8)
    {
        throw std::runtime_error("bad sign"); // create
    }

    CAdES cades = MyCryptoLib::CAdES(signMap);

    if (!caSign.empty())
    {
        pos = 0;
        std::map<int, std::vector<uint8_t>> caSignMap;
        while (pos < caSign.size())
        {
            // INCREMENT ALERT
            fieldSize |= (caSign[pos++] << 8);
            fieldSize |= (caSign[pos++]     );

            if (!(0 < fieldSize && fieldSize < 65536)) // Просто ограничение на всякий случай
            {
                throw std::runtime_error("bad field size, cant read");
            }

            caSignMap[caSignMap.size()] = std::vector<uint8_t>(caSign.begin() + pos, caSign.begin() + pos + fieldSize);
            pos += fieldSize;
            fieldSize = 0;
        }

        if (caSignMap.size() != 4)
        {
            throw std::runtime_error("bad ca sign"); // create
        }

        cades.caSignData = caSignMap;
    }

    return cades;
}


MyCryptoLib::CAdES MyCryptoLib::CAdES::fromFile(const std::string &filename)
{
    std::ifstream pkcsFile(filename, std::ios::binary);
    if (!pkcsFile.is_open())
    {
        throw std::runtime_error("Cant open file: " + filename);
    }

    std::string pemHeader = "-----BEGIN CADES SIGNATURE-----";
    std::string pemTerminator = "-----END CADES SIGNATURE-----";

    pkcsFile.seekg(0, std::ios::end);
    size_t completeSize = pkcsFile.tellg();
    pkcsFile.seekg(0, std::ios::beg);

    size_t headerPos = 0;
    size_t terminatorPos = 0;
    size_t pos = 0;
    std::vector<uint8_t> fileBuffer(1024, 0x00);

    // Сначала найти хедер и терминатор в файле

    while (pos < completeSize)
    {
        pkcsFile.read(reinterpret_cast<char*>(fileBuffer.data()), fileBuffer.size());
        std::string marker(fileBuffer.begin(), fileBuffer.end());
        headerPos = marker.find(pemHeader);
        if (headerPos != std::string::npos)
        {
            headerPos += pos;
            break;
        }
        pos += 1024;
    }

    if (headerPos == std::string::npos)
    {
        throw MyCryptoLib::BadPKCSFileStructureException("Cant find pkcs sign header");
    }

    while (pos < completeSize)
    {
        pkcsFile.read(reinterpret_cast<char*>(fileBuffer.data()), fileBuffer.size());
        std::string marker(fileBuffer.begin(), fileBuffer.end());

        terminatorPos = marker.find(pemTerminator);
        if (terminatorPos != std::string::npos)
        {
            terminatorPos += pos;
            break;
        }
        pos += 1024;
    }

    if (terminatorPos == std::string::npos)
    {
        throw MyCryptoLib::BadPKCSFileStructureException("Cant find pkcs sign terminator");
    }

    if (terminatorPos < headerPos)
    {
        throw MyCryptoLib::BadPKCSFileStructureException("Confusing pkcs structure, cant read");
    }

    // Читаем подпись в fileBuffer
    pkcsFile.clear(); // читаем файл заново (а не чистим его)
    pkcsFile.seekg(headerPos + pemHeader.size(), std::ios::beg);
    fileBuffer.resize(completeSize - headerPos - pemTerminator.size() - pemHeader.size());
    pkcsFile.read(reinterpret_cast<char*>(fileBuffer.data()), fileBuffer.size());

    return MyCryptoLib::CAdES::parseBuffers(fileBuffer);
}


void MyCryptoLib::CAdES::appendCASign(uint64_t time, const std::vector<uint8_t> &pubKeyHash, const std::vector<uint8_t> &signedMessageDigest, const std::vector<uint8_t> &signature)
{
    this->caSignData[0] = { static_cast<uint8_t>(time >> 56), static_cast<uint8_t>(time >> 48),
                            static_cast<uint8_t>(time >> 40), static_cast<uint8_t>(time >> 32),
                            static_cast<uint8_t>(time >> 24), static_cast<uint8_t>(time >> 16),
                            static_cast<uint8_t>(time >> 8 ), static_cast<uint8_t>(time >> 0 ) };
    this->caSignData[1] = std::vector<uint8_t>(pubKeyHash.begin(), pubKeyHash.end());
    this->caSignData[2] = std::vector<uint8_t>(signedMessageDigest.begin(), signedMessageDigest.end());
    this->caSignData[3] = std::vector<uint8_t>(signature.begin(), signature.end());
}


bool MyCryptoLib::CAdES::isSignedByCA() const
{
    return !this->caSignData.empty();
}

uint8_t MyCryptoLib::CAdES::getVersion() const
{
    return this->signData.at(0)[0];
}

std::string MyCryptoLib::CAdES::getContentType() const
{
    std::vector<uint8_t> buf = this->signData.at(1);
    return std::string(buf.begin(), buf.end());
}

std::vector<uint8_t> MyCryptoLib::CAdES::getContentHash() const
{
    return this->signData.at(2);
}

std::string MyCryptoLib::CAdES::getSignerName() const
{
    std::vector<uint8_t> buf = this->signData.at(3);
    return std::string(buf.begin(), buf.end());
}

std::vector<uint8_t> MyCryptoLib::CAdES::getSignerKeyFingerprint() const
{
    return this->signData.at(4);
}

std::string MyCryptoLib::CAdES::getHashAlgorithmId() const
{
    std::vector<uint8_t> buf = this->signData.at(5);
    return std::string(buf.begin(), buf.end());
}

std::string MyCryptoLib::CAdES::getSignAlgorithmId() const
{
    std::vector<uint8_t> buf = this->signData.at(6);
    std::string algoId(buf.begin(), buf.end());
    return algoId;
}

std::vector<uint8_t> MyCryptoLib::CAdES::getSignature() const
{
    return this->signData.at(7);
}

uint64_t MyCryptoLib::CAdES::getCATimestamp() const
{
    if (!this->isSignedByCA())
    {
        throw std::runtime_error("is not signed");
    }
    std::vector<uint8_t> timestamp = this->caSignData.at(0);

    return (static_cast<uint64_t>(timestamp[0]) << 56 |
            static_cast<uint64_t>(timestamp[1]) << 48 |
            static_cast<uint64_t>(timestamp[2]) << 40 |
            static_cast<uint64_t>(timestamp[3]) << 32 |
            static_cast<uint64_t>(timestamp[4]) << 24 |
            static_cast<uint64_t>(timestamp[5]) << 16 |
            static_cast<uint64_t>(timestamp[6]) << 8  |
            static_cast<uint64_t>(timestamp[7]));
}

std::vector<uint8_t> MyCryptoLib::CAdES::getCAKeyFingerprint() const
{
    if (!this->isSignedByCA())
    {
        throw std::runtime_error("is not signed");
    }
    return this->caSignData.at(1);
}

std::vector<uint8_t> MyCryptoLib::CAdES::getCASignedMessageDigest() const
{
    if (!this->isSignedByCA())
    {
        throw std::runtime_error("is not signed");
    }
    return this->caSignData.at(2);
}

std::vector<uint8_t> MyCryptoLib::CAdES::getCASignature() const
{
    if (!this->isSignedByCA())
    {
        throw std::runtime_error("is not signed");
    }
    return this->caSignData.at(3);
}

size_t MyCryptoLib::CAdES::getUserSignHeaderPos() const
{
    return this->userSignHeaderPos;
}

size_t MyCryptoLib::CAdES::getUserSignTerminatorPos() const
{
     return this->userSignTerminatorPos;
}

size_t MyCryptoLib::CAdES::getCASignHeaderPos() const
{
    return this->caSignHeaderPos;
}

size_t MyCryptoLib::CAdES::getCASignTerminatorPos() const
{
    return this->caSignTerminatorPos;
}

std::vector<uint8_t> MyCryptoLib::CAdES::toBytes() const
{
    size_t signSize = 0;
    for (const std::pair<int, std::vector<uint8_t>> &pair : this->signData)
    {
        signSize += pair.second.size() + 2;
    }

    std::vector<uint8_t> result(signSize + CAdES::userSignHeader.size() + CAdES::userSignTerminator.size(), 0x00);
    std::vector<uint8_t> buffer;
    size_t pos = 0;
    size_t bufferSize = 0;

    std::copy(CAdES::userSignHeader.begin(), CAdES::userSignHeader.end(), result.begin());
    pos += CAdES::userSignHeader.size();
    for (int i = 0; i < this->signData.size(); i++)
    {
        buffer = this->signData.at(i);
        bufferSize = buffer.size();

        // INCREMENT ALERT
        // 0
        result[pos++] = bufferSize >> 8; // 0
        result[pos++] = bufferSize; // 1
        // 2
        std::copy(buffer.begin(), buffer.end(), result.begin() + pos);
        pos += bufferSize;
    }
    std::copy(CAdES::userSignTerminator.begin(), CAdES::userSignTerminator.end(), result.begin() + pos);
    pos += CAdES::userSignTerminator.size();

    if (!this->caSignData.empty())
    {
        for (const std::pair<int, std::vector<uint8_t>> &pair : this->caSignData)
        {
            signSize += pair.second.size() + 2;
        }

        result.resize(signSize + CAdES::caSignHeader.size() + CAdES::caSignTerminator.size() + CAdES::userSignHeader.size() + CAdES::userSignTerminator.size(), 0x00);
        std::copy(CAdES::caSignHeader.begin(), CAdES::caSignHeader.end(), result.begin() + pos);
        pos += CAdES::caSignHeader.size();
        for (int i = 0; i < this->caSignData.size(); i++)
        {
            buffer = this->caSignData.at(i);
            bufferSize = buffer.size();

            // INCREMENT ALERT
            // 0
            result[pos++] = bufferSize >> 8; // 0
            result[pos++] = bufferSize; // 1
            // 2
            std::copy(buffer.begin(), buffer.end(), result.begin() + pos);
            pos += bufferSize;
        }
        std::copy(CAdES::caSignTerminator.begin(), CAdES::caSignTerminator.end(), result.end() - CAdES::caSignTerminator.size());
    }

    return result;
}


std::vector<uint8_t> MyCryptoLib::CAdES::toPem() const
{
    std::stringstream ss;
    std::string b64string = Base64::b64Encode(this->toBytes());

//    ss << pemHeader << '\n';

//    // wrap
//    for (int i = 0; i < b64string.size(); i++)
//    {
//        if (i % 80 == 0 && i != 0)
//        {
//            ss << '\n';
//        }
//        ss << b64string[i];
//    }
//    ss << '\n' << pemTerminator << '\n';

//    b64string = ss.str();

    return std::vector<uint8_t>(b64string.begin(), b64string.end());
}
