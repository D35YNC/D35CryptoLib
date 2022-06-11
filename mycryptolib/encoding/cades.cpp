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

MyCryptoLib::CAdES MyCryptoLib::CAdES::fromFileBytes(std::vector<uint8_t> &buffer)
{
    std::string pemHeader = "-----BEGIN CADES SIGNATURE-----";
    std::string pemTerminator = "-----END CADES SIGNATURE-----";

    size_t headerPos = 0;
    size_t terminatorPos = 0;
    size_t pos = 0;
    // Сначала найти хедер и терминатор в файле

    while (pos < buffer.size())
    {
        std::string marker(buffer.begin() + pos, buffer.begin() + pos + 1024);
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

    while (pos < buffer.size())
    {
        std::string marker(buffer.begin() + pos, buffer.begin() + pos + 1024);
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

    std::vector<uint8_t> signBuffer(buffer.begin() + headerPos + pemHeader.size(), buffer.begin() + terminatorPos);
    buffer.resize(headerPos);

    return MyCryptoLib::CAdES::fromBytes(signBuffer);
}


MyCryptoLib::CAdES MyCryptoLib::CAdES::fromBytes(const std::vector<uint8_t> &buffer)
{
    size_t pos = 0;
    size_t size = 0;
    size_t fieldSize = 0;
    std::map<int, std::vector<uint8_t>> signMap;

    if (!(buffer[0] == buffer[2] && buffer[0] == 0x0E &&
          buffer[1] == buffer[3] && buffer[1] == 0x51))
    {
        throw std::runtime_error("Bad struct"); // Create
    }
    pos += 4;

    size |= (buffer[pos++] << 8);
    size |= (buffer[pos++]     );

    while (pos < size) //??
    {
        // INCREMENT ALERT
        fieldSize |= (buffer[pos++] << 8);
        fieldSize |= (buffer[pos++]     );

        if (!(0 < fieldSize && fieldSize < 65536)) // Просто ограничение на всякий случай
        {
            throw std::runtime_error("bad field size, cant read");
        }

        signMap[signMap.size()] = std::vector<uint8_t>(buffer.begin() + pos, buffer.begin() + pos + fieldSize);
        pos += fieldSize;
        fieldSize = 0;
    }

    if (signMap.size() != 8)
    {
        throw std::runtime_error("bad sign"); // create
    }

    CAdES cades = MyCryptoLib::CAdES(signMap);

    if (pos < buffer.size())
    {         //// CHEKC
        if (!(buffer[pos] == buffer[pos + 2] && buffer[pos] == 0xCA &&
              buffer[pos + 1] == buffer[pos + 3] && buffer[pos + 1] == 0x51))
        {
            throw std::runtime_error("Bad struct"); // Create
        }
        pos += 4;

        size = 0;
        size |= (buffer[pos++] << 8);
        size |= (buffer[pos++]     );

        std::map<int, std::vector<uint8_t>> caSignMap;
        while (pos - size < size) //??
        {
            // INCREMENT ALERT
            fieldSize |= (buffer[pos++] << 8);
            fieldSize |= (buffer[pos++]     );

            if (!(0 < fieldSize && fieldSize < 65536)) // Просто ограничение на всякий случай
            {
                throw std::runtime_error("bad field size, cant read");
            }

            caSignMap[caSignMap.size()] = std::vector<uint8_t>(buffer.begin() + pos, buffer.begin() + pos + fieldSize);
            pos += fieldSize;
            fieldSize = 0;
        }

        if (caSignMap.size() != 3)
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

    return MyCryptoLib::CAdES::fromBytes(fileBuffer);
}


void MyCryptoLib::CAdES::appendCASign(uint64_t time, const std::vector<uint8_t> &pubKeyHash, const std::vector<uint8_t> &signature)
{
    this->caSignData[0] = { static_cast<uint8_t>(time << 56 & 0xFF), static_cast<uint8_t>(time << 48 & 0xFF),
                            static_cast<uint8_t>(time << 40 & 0xFF), static_cast<uint8_t>(time << 32 & 0xFF),
                            static_cast<uint8_t>(time << 24 & 0xFF), static_cast<uint8_t>(time << 16 & 0xFF),
                            static_cast<uint8_t>(time << 8  & 0xFF), static_cast<uint8_t>(time << 0  & 0xFF) };
    this->caSignData[1] = std::vector<uint8_t>(pubKeyHash.begin(), pubKeyHash.end());
    this->caSignData[2] = std::vector<uint8_t>(signature.begin(), signature.end());
}

void MyCryptoLib::CAdES::setCASignData(const std::map<int, std::vector<uint8_t> > &caSign)
{
    this->caSignData = caSign;
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

std::vector<uint8_t> MyCryptoLib::CAdES::getCASignature() const
{
    if (!this->isSignedByCA())
    {
        throw std::runtime_error("is not signed");
    }
    return this->caSignData.at(2);
}


std::vector<uint8_t> MyCryptoLib::CAdES::toBytes(bool includeHeaders) const
{
    size_t signSize = 0;
    for (const std::pair<int, std::vector<uint8_t>> &pair : this->signData)
    {
        signSize += pair.second.size() + 2;
    }

    std::vector<uint8_t> result(signSize + 6, 0x00);
    std::vector<uint8_t> buffer;
    size_t pos = 0;
    size_t bufferSize = 0;

    // My Sign Header
    result[pos++] = 0x0E;
    result[pos++] = 0x51;
    result[pos++] = 0x0E;
    result[pos++] = 0x51;
    result[pos++] = signSize >> 8; // 0
    result[pos++] = signSize; // 1

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

    if (!this->caSignData.empty())
    {
        size_t caSignSize = 0;
        for (const std::pair<int, std::vector<uint8_t>> &pair : this->caSignData)
        {
            caSignSize += pair.second.size() + 2;
        }

        result.resize(signSize + caSignSize + 12);

        // CA Sign Header
        result[pos++] = 0xCA;
        result[pos++] = 0x51;
        result[pos++] = 0xCA;
        result[pos++] = 0x51;
        result[pos++] = caSignSize >> 8;
        result[pos++] = caSignSize;

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
    }

    if (includeHeaders)
    {
        std::vector<uint8_t> wrapped(result.size() + this->pemHeader.size() + this->pemTerminator.size(), 0x00);

        std::copy(this->pemHeader.begin(), this->pemHeader.end(), wrapped.begin());
        std::copy(result.begin(), result.end(), wrapped.begin() + this->pemHeader.size());
        std::copy(this->pemTerminator.begin(), this->pemTerminator.end(), wrapped.begin() + this->pemHeader.size() + result.size());

        result = wrapped;
    }


    return result;
}


std::vector<uint8_t> MyCryptoLib::CAdES::toPem() const
{
    std::stringstream ss;
    std::string b64string = Base64::b64Encode(this->toBytes(false));

    ss << pemHeader << '\n';

    // wrap
    for (int i = 0; i < b64string.size(); i++)
    {
        if (i % 80 == 0 && i != 0)
        {
            ss << '\n';
        }
        ss << b64string[i];
    }
    ss << '\n' << pemTerminator << '\n';

    b64string = ss.str();

    return std::vector<uint8_t>(b64string.begin(), b64string.end());
}
