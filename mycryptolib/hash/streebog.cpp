#include "streebog.h"

void MyCryptoLib::Streebog::_init()
{
    std::fill(h.begin(), h.end(), this->digestSize() == 32 ? 0x01 : 0x00);
    std::fill(N.begin(), N.end(), 0x00);
    std::fill(Sigma.begin(), Sigma.end(), 0x00);
}

void MyCryptoLib::Streebog::update(const std::string &data)
{
    this->update(std::vector<uint8_t>(data.begin(), data.end()));
}

void MyCryptoLib::Streebog::update(const std::vector<uint8_t> &data)
{
    std::vector<uint8_t> buffer = data;
    std::reverse(buffer.begin(), buffer.end());

    this->_init();
    this->_updateState(buffer);
    this->_finalize(buffer);
}

void MyCryptoLib::Streebog::update(std::ifstream &file, size_t bytesCount)
{
    if (!file.is_open())
    {
        return; // elpase execpions
    }

    this->_init();

    // get file size

    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    if (0 > bytesCount && bytesCount <= fileSize)
    {
        fileSize = bytesCount;
    }
    else if (bytesCount > fileSize)
    {
        std::runtime_error("Cant read > bytes than file size");
    }

    //process first I full blocks
    std::vector<uint8_t> readBuffer(4096);
    for (int i = 0; i < (int)(fileSize / 4096); i++)
    {
        file.read((char*)readBuffer.data(), readBuffer.size());
        std::reverse(readBuffer.begin(), readBuffer.end());
        this->_updateState(readBuffer); // ALERT SLOW SLOW AMOFUS
        readBuffer.resize(4096);
    }

    //process last block wth padding
    int lastBlockSize = (int)(fileSize % 4096);
    readBuffer.resize(lastBlockSize);
    file.read((char*)readBuffer.data(), readBuffer.size());
    std::reverse(readBuffer.begin(), readBuffer.end());
    this->_pad(readBuffer);
    this->_updateState(readBuffer);
    this->_finalize(readBuffer);
}

size_t MyCryptoLib::Streebog::blockSize()
{
    return 64;
}

void MyCryptoLib::Streebog::_updateState(std::vector<uint8_t> &buffer)
{
    std::vector<uint8_t> v512(64, 0x00);
    v512[62] = 0x02; // 512 -> 64 uint8

    while (buffer.size() >= 64)
    {
        std::vector<uint8_t> block(buffer.end() - 64, buffer.end()); // 64 bytes с конца
        buffer.erase(buffer.end() - 64, buffer.end()); // Резня

        h = _compress(N, h, block);
        N = _add512(N, v512);
        Sigma = _add512(Sigma, block);
    }
}

void MyCryptoLib::Streebog::_pad(std::vector<uint8_t> &buffer)
{
    if (buffer.size() < 64)
    {
        std::vector<uint8_t> paddedData(64, 0x00);
        paddedData[64 - buffer.size() - 1] = 0x01;
        std::copy(buffer.begin(), buffer.end(), paddedData.begin() + (64 - buffer.size()));
        buffer = paddedData;
    }
}

void MyCryptoLib::Streebog::_finalize(std::vector<uint8_t> &buffer)
{
    std::vector<uint8_t> v512_0(64, 0x00); // 512 0000
    std::vector<uint8_t> v512(64, 0x00);

    uint32_t msgBitSize = buffer.size() * 8;
    v512[60] = (uint8_t)(msgBitSize >> 24);
    v512[61] = (uint8_t)(msgBitSize >> 16);
    v512[62] = (uint8_t)(msgBitSize >> 8);
    v512[63] = (uint8_t)(msgBitSize);

    this->_pad(buffer);

    h = _compress(N, h, buffer);

    N = _add512(N, v512);
    Sigma = _add512(Sigma, buffer);

    h = _compress(v512_0, h, N);
    h = _compress(v512_0, h, Sigma);

    std::reverse(h.begin(), h.end());

    if (this->digestSize() == 32)
    {
        std::copy(h.begin() + 32, h.end(), this->_digest.begin());
    }
    else
    {
        this->_digest = h;
    }
}

void MyCryptoLib::Streebog::setMode(int __digestSize)
{
    if (!(__digestSize == 256 | __digestSize == 512))
    {
        throw "Incorrect digest size. Must be 256 or 512";
    }
    this->_setNewDigestSize(__digestSize);
    this->_name = "Streebog" + std::to_string(__digestSize);
}

std::vector<uint8_t> MyCryptoLib::Streebog::_add512(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b)
{
    std::vector<uint8_t> result(64, 0x00);
    uint32_t tmp = 0;

    for (int i = 63; i >= 0; i--)
    {
        tmp = a[i] + b[i] + (tmp >> 8);
        result[i] = (uint8_t)(tmp & 0xff);
    }

    return result;
}

std::vector<uint8_t> MyCryptoLib::Streebog::_xor512(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b)
{
    std::vector<uint8_t> result(64, 0x00);
    for (int i = 0; i < 64; i++)
    {
        result[i] = (uint8_t)(a[i] ^ b[i]);
    }

    return result;
}

std::vector<uint8_t> MyCryptoLib::Streebog::_getIterKey(const std::vector<uint8_t> &k, int i)
{
    std::vector<uint8_t> result(64, 0x00);
    result = this->_xor512(k, this->C[i]);
    result = this->_lpsTransform(result);
    return result;
}

std::vector<uint8_t> MyCryptoLib::Streebog::_lpsTransform(const std::vector<uint8_t> &state)
{
    // S
    uint8_t sTransformed[64] = { 0x00 };
    for (int i = 0; i < 64; i++)
    {
        sTransformed[i] = this->pi[state[i]];
    }

    // P
    uint8_t pTransformed[64] = { 0x00 };
    for (int i = 0; i < 64; i++)
    {
        pTransformed[i] = sTransformed[this->tau[i]];
    }

    // L
    std::vector<uint8_t> result(64, 0x00);
    for (int i = 0; i < 8; i++)
    {
        uint64_t tmp64Result = 0;

        uint64_t tmp64 = ((uint64_t)pTransformed[i * 8] << 56) |
                ((uint64_t)pTransformed[(i * 8) + 1] << 48) |
                ((uint64_t)pTransformed[(i * 8) + 2] << 40) |
                ((uint64_t)pTransformed[(i * 8) + 3] << 32) |
                ((uint64_t)pTransformed[(i * 8) + 4] << 24) |
                ((uint64_t)pTransformed[(i * 8) + 5] << 16) |
                ((uint64_t)pTransformed[(i * 8) + 6] << 8) |
                ((uint64_t)pTransformed[(i * 8) + 7]);

        for (int j = 0; j < 64; j++)
        {
            if ((tmp64 >> (63 - j)) & 1)
            {
                tmp64Result ^= A[j];
            }
        }

        result[i * 8] = (uint8_t)(tmp64Result >> 56);
        result[(i * 8) + 1] = (uint8_t)(tmp64Result >> 48);
        result[(i * 8) + 2] = (uint8_t)(tmp64Result >> 40);
        result[(i * 8) + 3] = (uint8_t)(tmp64Result >> 32);
        result[(i * 8) + 4] = (uint8_t)(tmp64Result >> 24);
        result[(i * 8) + 5] = (uint8_t)(tmp64Result >> 16);
        result[(i * 8) + 6] = (uint8_t)(tmp64Result >> 8);
        result[(i * 8) + 7] = (uint8_t)(tmp64Result);
    }

    return result;
}

std::vector<uint8_t> MyCryptoLib::Streebog::_eTranform(const std::vector<uint8_t> &k, const std::vector<uint8_t> &m)
{
    std::vector<uint8_t> result = this->_xor512(m, k);
    std::vector<uint8_t> _K = k;

    for (int i = 0; i < 12; i++)
    {
        result = this->_lpsTransform(result);
        _K = this->_getIterKey(_K, i);
        result = this->_xor512(result, _K);
    }

    return result;
}

std::vector<uint8_t> MyCryptoLib::Streebog::_compress(const std::vector<uint8_t> &N, const std::vector<uint8_t> &h, const std::vector<uint8_t> &m)
{
    std::vector<uint8_t> k = this->_xor512(N, h);
    k = this->_lpsTransform(k);

    std::vector<uint8_t> tmp = this->_eTranform(k, m);
    tmp = this->_xor512(tmp, h);
    tmp = this->_xor512(tmp, m);

    return tmp;
}
