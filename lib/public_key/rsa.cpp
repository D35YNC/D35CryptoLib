#include "rsa.h"

#include "../utils.h"

std::vector<uint8_t> D35Crypto::RSA::encrypt(const std::vector<uint8_t> &data, const RSAKey &key)
{
    if (!key.canEncrypt())
    {
        throw D35Crypto::WrongKeyException(__LINE__, __FILE__, "Public key need for encryption");
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


std::vector<uint8_t> D35Crypto::RSA::decrypt(const std::vector<uint8_t> &data, const RSAKey &key)
{
    if (!key.canDecrypt())
    {
        throw D35Crypto::WrongKeyException(__LINE__, __FILE__, "Private key need for decrypt");
    }

    if (data.size() % key.size() != 0)
    {
        throw D35Crypto::BadKeySizeException(__LINE__, __FILE__/*, "Data not padded"*/); // ?
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


void D35Crypto::RSA::crypt(std::vector<uint8_t> &data, const NTL::ZZ &power, const NTL::ZZ &n)
{
    NTL::ZZ intData = NTL::ZZFromBytes(data.data(), data.size());
    NTL::ZZ intResult = NTL::PowerMod(intData, power, n);
    data.resize(NTL::NumBytes(n));

    NTL::BytesFromZZ(data.data(), intResult, data.size());
}


void D35Crypto::RSA::pad(std::vector<uint8_t> &data, size_t blockSize)
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


void D35Crypto::RSA::unpad(std::vector<uint8_t> &data)
{
    int zerosCount = data[data.size() - 1];
    std::vector<uint8_t> result(data.begin(), data.begin() + (data.size() - zerosCount));
    data = result;
}
