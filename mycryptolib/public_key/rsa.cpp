#include "rsa.h"

#include "../utils.h"

std::vector<uint8_t> MyCryptoLib::RSA::encrypt(const std::vector<uint8_t> &data, const RSAKey &key)
{
    if (!key.canEncrypt())
    {
        throw MyCryptoLib::WrongKeyException("Public key need for encrypt");
    }

    std::vector<uint8_t> paddedData(data.begin(), data.end());
    if (paddedData.size() % key.size() != 0)
    {
        this->pad(paddedData, key.blockSize());
    }

    std::vector<uint8_t> encryptedData;
    encryptedData.reserve(paddedData.size());
    int blocksCount = static_cast<int>(paddedData.size() / key.blockSize());
    for (int i = 0; i < blocksCount; i++)
    {
        std::vector<uint8_t> block(paddedData.begin() + (i * key.blockSize()), paddedData.begin() + (i * key.blockSize()) + key.blockSize());
        this->crypt(block, key.getPublicExponent(), key.getModulus());
        std::copy(block.begin(), block.end(), std::back_inserter(encryptedData));
    }
    return encryptedData;
}


std::vector<uint8_t> MyCryptoLib::RSA::decrypt(const std::vector<uint8_t> &data, const RSAKey &key)
{
    if (!key.canDecrypt())
    {
        throw MyCryptoLib::WrongKeyException("Private key need for decrypt");
    }

    if (data.size() % key.size() != 0)
    {
        throw std::exception();//creat
    }

    std::vector<uint8_t> decryptedData;
    decryptedData.reserve(data.size());

    int blocksCount = static_cast<int>(data.size() / key.size());
    for (int i = 0; i < blocksCount; i++)
    {
        std::vector<uint8_t> block(data.begin() + (i * key.size()), data.begin() + (i * key.size()) + key.size());
        this->crypt(block, key.getPrivateExponent(), key.getModulus());
        std::copy(block.begin(), block.begin() + key.blockSize(), std::back_inserter(decryptedData));
    }
    unpad(decryptedData);
    return decryptedData;
}


MyCryptoLib::PKCS7 MyCryptoLib::RSA::encrypt(const std::string &dataType, const std::vector<uint8_t> &data, const RSAKey &key)
{
    return MyCryptoLib::PKCS7::create(0, dataType, "RSA-RAW", this->encrypt(data, key));
}


std::vector<uint8_t> MyCryptoLib::RSA::decrypt(const PKCS7 &pkcs7obj, const RSAKey &key)
{
    return this->decrypt(pkcs7obj.getData(), key);
}


MyCryptoLib::CAdES MyCryptoLib::RSA::sign(
        const std::string &username,
        const std::vector<uint8_t> &pubKeyHash,
        const std::string &data,
        MyCryptoLib::HashBase *hash,
        const RSAKey &key)
{
    return MyCryptoLib::RSA::sign(username, pubKeyHash, "TEXT", std::vector<uint8_t>(data.begin(), data.end()), hash, key);
}


MyCryptoLib::CAdES MyCryptoLib::RSA::sign(
        const std::string &username,
        const std::vector<uint8_t> &pubKeyHash,
        const std::string &contentType,
        const std::vector<uint8_t> &data,
        MyCryptoLib::HashBase *hash,
        const RSAKey &key)
{
    hash->update(data);
    std::vector<uint8_t> originalHash = hash->digest();
    std::vector<uint8_t> signature = hash->digest();

    this->crypt(signature, key.getPrivateExponent(), key.getModulus());
    return CAdES::create(1, contentType, username, pubKeyHash, hash->name(), "RSAdsi", originalHash, signature);
}


MyCryptoLib::CAdES MyCryptoLib::RSA::sign(
        const std::string &username,
        const std::vector<uint8_t> &pubKeyHash,
        const std::string &contentType,
        const std::string &filename,
        MyCryptoLib::HashBase *hash,
        const RSAKey &key)
{
    std::ifstream signingFile(filename);
    hash->update(signingFile);
    std::vector<uint8_t> originalHash = hash->digest();
    std::vector<uint8_t> signature = hash->digest();

    this->crypt(signature, key.getPrivateExponent(), key.getModulus());
    return CAdES::create(1, contentType, username, pubKeyHash, hash->name(), "RSAdsi", originalHash, signature);
}

void MyCryptoLib::RSA::signCA(CAdES &userCAdES, const std::vector<uint8_t> &caPubKeyHash, const std::vector<uint8_t> &signedMessage, const RSAKey &key)
{
    // gEt timestamp
    auto now = std::chrono::system_clock::now();
    uint64_t timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();

    // prepare data with timestamp
    std::vector<uint8_t> dataForSigning(signedMessage.begin(), signedMessage.end());
    size_t datasize = dataForSigning.size();
    dataForSigning.resize(datasize + 8);
    dataForSigning[datasize    ] = static_cast<uint8_t>(timestamp >> 56);
    dataForSigning[datasize + 1] = static_cast<uint8_t>(timestamp >> 48);
    dataForSigning[datasize + 2] = static_cast<uint8_t>(timestamp >> 40);
    dataForSigning[datasize + 3] = static_cast<uint8_t>(timestamp >> 32);
    dataForSigning[datasize + 4] = static_cast<uint8_t>(timestamp >> 24);
    dataForSigning[datasize + 5] = static_cast<uint8_t>(timestamp >> 16);
    dataForSigning[datasize + 6] = static_cast<uint8_t>(timestamp >> 8 );
    dataForSigning[datasize + 7] = static_cast<uint8_t>(timestamp >> 0 );

    HashBase *hash = MyCryptoLib::hashIdToHashPtr(userCAdES.getHashAlgorithmId());
    hash->update(dataForSigning);
    std::vector<uint8_t> signature = hash->digest();
    hash->update(signedMessage);
    std::vector<uint8_t> signedMessageDigest = hash->digest();
    delete hash;

    crypt(signature, key.getPrivateExponent(), key.getModulus());

    userCAdES.appendCASign(timestamp, caPubKeyHash, signedMessageDigest, signature);
}


bool MyCryptoLib::RSA::checkSign(const std::vector<uint8_t> &userSignedMessage, const MyCryptoLib::CAdES &cades, const RSAKey &key)
{
    std::vector<uint8_t> digest = cades.getContentHash();
    std::vector<uint8_t> signature = cades.getSignature();

    this->crypt(signature, key.getPublicExponent(), key.getModulus());
    signature.resize(digest.size());

    if (!userSignedMessage.empty())
    {
        HashBase *hash = MyCryptoLib::hashIdToHashPtr(cades.getHashAlgorithmId());
        hash->update(std::vector<uint8_t>(userSignedMessage.begin(), userSignedMessage.begin() + cades.getUserSignHeaderPos()));
        std::vector<uint8_t> actualDigest = hash->digest();
        delete hash;
        return digest == actualDigest && digest == signature;
    }
    return digest == signature;
}

bool MyCryptoLib::RSA::checkCASign(const std::vector<uint8_t> &signedMessage, const CAdES &cades, const RSAKey &caPubKey)
{
    std::vector<uint8_t> signedMessageDigest = cades.getCASignedMessageDigest();
    std::vector<uint8_t> signature = cades.getCASignature();
    uint64_t timestamp = cades.getCATimestamp();

    this->crypt(signature, caPubKey.getPublicExponent(), caPubKey.getModulus());
    signature.resize(signedMessageDigest.size());

    std::vector<uint8_t> data(signedMessage.begin(), signedMessage.begin() + cades.getCASignHeaderPos());
    size_t dataSize = data.size();
    HashBase *hash = MyCryptoLib::hashIdToHashPtr(cades.getHashAlgorithmId());
    hash->update(data);
    if (hash->digest() != cades.getCASignedMessageDigest())
    {
        return false; // corrupted message/sign/ca sign
    }

    data.resize(dataSize + 8);
    data[dataSize    ] = static_cast<uint8_t>(timestamp >> 56);
    data[dataSize + 1] = static_cast<uint8_t>(timestamp >> 48);
    data[dataSize + 2] = static_cast<uint8_t>(timestamp >> 40);
    data[dataSize + 3] = static_cast<uint8_t>(timestamp >> 32);
    data[dataSize + 4] = static_cast<uint8_t>(timestamp >> 24);
    data[dataSize + 5] = static_cast<uint8_t>(timestamp >> 16);
    data[dataSize + 6] = static_cast<uint8_t>(timestamp >> 8 );
    data[dataSize + 7] = static_cast<uint8_t>(timestamp >> 0 );

    hash->update(data);
    std::vector<uint8_t> actualDigest = hash->digest();
    delete hash;

    return actualDigest  == signature;
}


void MyCryptoLib::RSA::crypt(std::vector<uint8_t> &data, const NTL::ZZ &power, const NTL::ZZ &n)
{
    NTL::ZZ intData = NTL::ZZFromBytes(data.data(), data.size());
    NTL::ZZ intResult = NTL::PowerMod(intData, power, n);
    data.resize(NTL::NumBytes(n));

    NTL::BytesFromZZ(data.data(), intResult, data.size());
}


void MyCryptoLib::RSA::pad(std::vector<uint8_t> &data, size_t blockSize)
{
    std::vector<uint8_t> result(blockSize - (data.size() % blockSize) + data.size(), 0x00);

//    std::copy(data.begin(), data.end(), result.end() - data.size());
    std::copy(data.begin(), data.end(), result.begin());

    size_t zerosCount = result.size() - data.size(); // zeros count
    if (zerosCount > 1)
    {
        result[result.size() - 1] = static_cast<uint8_t>(zerosCount);
    }
    data = result;
}


void MyCryptoLib::RSA::unpad(std::vector<uint8_t> &data)
{
    int zerosCount = data[data.size() - 1];
    std::vector<uint8_t> result(data.begin(), data.begin() + (data.size() - zerosCount));
    data = result;
}
