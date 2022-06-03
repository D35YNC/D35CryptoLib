#include "hmac.h"


MyCryptoLib::HMAC::HMAC(HashBase *hmacHash)
{
    if (hmacHash == nullptr)
    {
        throw std::invalid_argument("hash is nullptr");
    }

    this->hash = hmacHash;
}

void MyCryptoLib::HMAC::create(const std::string &data, const Key &key)
{
    this->create(std::vector<uint8_t>(data.begin(), data.end()), key);
}

void MyCryptoLib::HMAC::create(const std::vector<uint8_t> &data, const Key &key)
{
    // static_assert(std::is_base_of<IHash, Hash>::value, "IHash needeed");

    // СЛИШКОМ МНОГО АЛЛОКАЦИЙ
    // FIXIFIFIFX

    std::vector<uint8_t> paddedKey = key.raw();
    paddedKey.resize(this->hash->blockSize());          // Обрезать/увеличить

    if (key.size() < this->hash->blockSize())           // Дополнить справа нулями
    {
        std::fill(paddedKey.begin() + key.size(), paddedKey.end(), 0x00);
    }

    std::vector<uint8_t> ipad((int)(this->hash->blockSize()), 0x36); // 00110110
    std::vector<uint8_t> opad((int)(this->hash->blockSize()), 0x5c); // 01011100

    std::vector<uint8_t> tmp_rigth_part = this->xorBlocks(paddedKey, ipad);

    std::copy(data.begin(), data.end(), std::back_inserter(tmp_rigth_part));

    this->hash->update(tmp_rigth_part);
    tmp_rigth_part = this->hash->digest();

    std::vector<uint8_t> tmp_left_part = this->xorBlocks(paddedKey, opad);
    std::copy(tmp_rigth_part.begin(), tmp_rigth_part.end(), std::back_inserter(tmp_left_part));
    this->hash->update(tmp_left_part);

    this->hmac = this->hash->digest();
}

void MyCryptoLib::HMAC::setHash(HashBase *hmacHash)
{
    if (hmacHash == nullptr)
    {
        throw std::invalid_argument("hash is nullptr");
    }

    this->hash = hmacHash;
}

std::vector<uint8_t> MyCryptoLib::HMAC::raw()
{
    return this->hmac;
}

std::string MyCryptoLib::HMAC::hex()
{
    std::stringstream ss;
    ss << std::setfill('0') << std::hex;

    for (int i = 0; i < this->hmac.size(); i++)
    {
        ss << std::setw(2) << (unsigned int)(this->hmac[i]);
    }

    return ss.str();
}

std::string MyCryptoLib::HMAC::name()
{
    return "HMAC-" + this->hash->name();
}

std::vector<uint8_t> MyCryptoLib::HMAC::xorBlocks(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b)
{
    int blockSize = a.size() ? a.size() <= b.size() : b.size();
    // С одной стороны можно выбрасывать исключение, но это же приватный метод, да и в любом случае такой ситуации возникнуть не должно тк размер а==б
    std::vector<uint8_t> result(blockSize);

    for (int i = 0; i < blockSize; i++)
    {
        result[i] = a[i] ^ b[i];
    }
    return result;
}
