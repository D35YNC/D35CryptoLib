#include "rsa.h"

std::vector<uint8_t> MyCryptoLib::RSA::encrypt(const std::vector<uint8_t> &data, const RSAKey &key)
{
    if (!key.canEncrypt())
    {
        throw MyCryptoLib::WrongKeyException("Public key need for encrypt");
    }
    std::vector<uint8_t> paddedData = data;
    if (paddedData.size() % key.size() != 0)
    {
        this->pad(paddedData, key.size());
    }

    this->crypt(paddedData, key.getPublicExponent(), key.getModulus());
    return paddedData;

//    std::vector<uint8_t> encryptedData;
//    for (int i = 0; i < static_cast<int>(paddedData.size() / key.size()); i++)
//    {
//        std::vector<uint8_t> block(paddedData.begin() + (i * key.size()), paddedData.begin() + (i * key.size()) + key.size());
//        this->crypt(block, key.getPublicExponent(), key.getModulus());
//        std::copy(block.begin(), block.end(), std::back_inserter(encryptedData));
//    }
//    return encryptedData;
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

    std::vector<uint8_t> decryptedData = data;
//    decryptedData.reserve(data.size());
    this->crypt(decryptedData, key.getPrivateExponent(), key.getModulus());
//    for (int i = 0; i < static_cast<int>(data.size() / key.size()); i++)
//    {
//        std::vector<uint8_t> block(data.begin() + (i * key.size()), data.begin() + (i * key.size()) + key.size());
//        this->crypt(block, key.getPrivateExponent(), key.getModulus());
//        std::copy(block.begin(), block.end(), std::back_inserter(decryptedData));
//    }
    return decryptedData;
}

MyCryptoLib::PKCS7 MyCryptoLib::RSA::encrypt(const std::string &dataType, const std::vector<uint8_t> &data, const RSAKey &key)
{
    return MyCryptoLib::PKCS7::packEncryptedPKCS7(0, dataType, "RSA-RAW", this->encrypt(data, key));
}

//MyCryptoLib::PKCS7 MyCryptoLib::RSA::signPKCS7(MyCryptoLib::IHash *hash, const std::vector<uint8_t> &data, const RSAKey &key)
//{
//    if (hash == nullptr)
//    {
//        throw std::exception();
//    }
//    hash->update(data);
//    std::vector<uint8_t> digest = hash->digest();
//    return PKCS7(1, "data", "D35YNC", hash->name(), "RSA-RAW", this->encrypt(digest, key));
//}

void MyCryptoLib::RSA::crypt(std::vector<uint8_t> &data, const NTL::ZZ &power, const NTL::ZZ &n)
{
    NTL::ZZ intData = NTL::ZZFromBytes(data.data(), data.size());
    NTL::ZZ intResult = NTL::PowerMod(intData % n, power, n);
    NTL::BytesFromZZ(data.data(), intResult, data.size());
}

void MyCryptoLib::RSA::pad(std::vector<uint8_t> &data, size_t blockSize)
{
    std::vector<uint8_t> result(blockSize, 0x00);
//    size_t oldSize = data.size();
//    data.resize(blockSize - (oldSize % blockSize) + oldSize);

    std::copy(data.begin(), data.end(), result.end() - data.size());
    data = result;

//    oldSize -= data.size(); // zeros count
//    if (oldSize > 2)
//    {
//        data[data.size() - 1] = static_cast<uint8_t>(oldSize);
//        data[data.size() - 2] = static_cast<uint8_t>(oldSize >> 8);
//    }
}
