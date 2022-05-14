#include "sha256.h"


void MyCryptoLib::SHA256::_init()
{
    this->_hashState[0] = 0x6A09E667;
    this->_hashState[1] = 0xBB67AE85;
    this->_hashState[2] = 0x3C6EF372;
    this->_hashState[3] = 0xA54FF53A;
    this->_hashState[4] = 0x510E527F;
    this->_hashState[5] = 0x9B05688C;
    this->_hashState[6] = 0x1F83D9AB;
    this->_hashState[7] = 0x5BE0CD19;
}

void MyCryptoLib::SHA256::update(const std::string &data)
{
    this->update(std::vector<uint8_t>(data.begin(), data.end()));
}

void MyCryptoLib::SHA256::update(const std::vector<uint8_t> &data)
{
    std::vector<uint8_t> buffer = data;
    this->_init();
    this->_pad(buffer, data.size());
    this->_updateState(buffer);
    this->_finalize();
}

void MyCryptoLib::SHA256::update(std::ifstream &data)
{
    if (!data.is_open())
    {
        return; // elpase execpions
    }

    this->_init();

    // get file size
    data.seekg(0, std::ios::end);
    size_t fileSize = data.tellg();
    data.seekg(0, std::ios::beg);

    //process first I full blocks
    std::vector<uint8_t> readBuffer(4096);
    for (int i = 0; i < (int)(fileSize / 4096); i++)
    {
        data.read((char*)readBuffer.data(), readBuffer.size());
        this->_updateState(readBuffer);
    }

    //process last block wth padding
    int lastBlockSize = (int)(fileSize % 4096);
    readBuffer.resize(lastBlockSize);
    data.read((char*)readBuffer.data(), readBuffer.size());

    this->_pad(readBuffer, fileSize);
    this->_updateState(readBuffer);
    this->_finalize();
}

size_t MyCryptoLib::SHA256::blockSize()
{
    return 64;
}

void MyCryptoLib::SHA256::_updateState(const std::vector<uint8_t> &buffer)
{
    int pos = 0;
    std::vector<uint32_t> block(64);
    while (pos < buffer.size())
    {
        for (int i = 0; i < 16; i++)
        {
            block[i] = ((uint32_t)(buffer[pos    ] << 24) |
                        (uint32_t)(buffer[pos + 1] << 16) |
                        (uint32_t)(buffer[pos + 2] <<  8) |
                        (uint32_t)(buffer[pos + 3]));

            pos += 4;
        }

        this->_processBlock(block);
    }
}

void MyCryptoLib::SHA256::_processBlock(std::vector<uint32_t> block)
{
    for (int i = 16; i < 64; i++)
    {
        block[i] = block[i - 16] +
                SHA256::Sigma0(block[i - 15]) +
                block[i-7] +
                SHA256::Sigma1(block[i - 2]);
    }

    // Мб в масисв это все засунуть

    uint32_t a = _hashState[0];
    uint32_t b = _hashState[1];
    uint32_t c = _hashState[2];
    uint32_t d = _hashState[3];
    uint32_t e = _hashState[4];
    uint32_t f = _hashState[5];
    uint32_t g = _hashState[6];
    uint32_t h = _hashState[7];

    for (int i = 0; i < 64; i++)
    {
        uint32_t t1 = h + SHA256::SIGMA1(e) + SHA256::Ch(e, f, g) + SHA256::CONSTS[i] + block[i];
        uint32_t t2 = SHA256::SIGMA0(a) + SHA256::Maj(a, b, c);

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    _hashState[0] += a;
    _hashState[1] += b;
    _hashState[2] += c;
    _hashState[3] += d;
    _hashState[4] += e;
    _hashState[5] += f;
    _hashState[6] += g;
    _hashState[7] += h;
}

void MyCryptoLib::SHA256::_pad(std::vector<uint8_t> &buffer, size_t datasize)
{
    uint64_t bitSize = datasize * 8;
    // Возможно баг тк дополняет полный размер а не размер блока
    // хотя возможно они равны из за кратности ччч
    int k = (448 - 1 - bitSize) % 512; // zeroes bits scount

    // fill '1' & k '0' // count in bytes
    buffer.push_back(0x80); // '1' & 7 zeroes
    for (int i = 1; i < int((k + 1) / 8); i++)
    {
        buffer.push_back(0x00); // 8 zeroes
    }

    // big endian size append
    // from 64 to 8
    buffer.push_back((uint8_t)(bitSize >> 56));
    buffer.push_back((uint8_t)(bitSize >> 48));
    buffer.push_back((uint8_t)(bitSize >> 40));
    buffer.push_back((uint8_t)(bitSize >> 32));
    buffer.push_back((uint8_t)(bitSize >> 24));
    buffer.push_back((uint8_t)(bitSize >> 16));
    buffer.push_back((uint8_t)(bitSize >> 8));
    buffer.push_back((uint8_t)(bitSize));
}

void MyCryptoLib::SHA256::_finalize()
{
    for (int i = 0; i < 8; i++)
    {
        this->_digest[i * 4] = (uint8_t)(_hashState[i] >> 24);
        this->_digest[(i * 4) + 1] = (uint8_t)(_hashState[i] >> 16);
        this->_digest[(i * 4) + 2] = (uint8_t)(_hashState[i] >> 8);
        this->_digest[(i * 4) + 3] = (uint8_t)(_hashState[i]);
    }
}


uint32_t MyCryptoLib::SHA256::Sigma0(uint32_t x)
{
    return SHA256::rotr(x, 7) ^ SHA256::rotr(x, 18) ^ (x >> 3);
}

uint32_t MyCryptoLib::SHA256::Sigma1(uint32_t x)
{
    return SHA256::rotr(x, 17) ^ SHA256::rotr(x, 19) ^ (x >> 10);
}

uint32_t MyCryptoLib::SHA256::SIGMA0(uint32_t x)
{
    return SHA256::rotr(x, 2) ^ SHA256::rotr(x, 13) ^ SHA256::rotr(x, 22);
}

uint32_t MyCryptoLib::SHA256::SIGMA1(uint32_t x)
{
    return SHA256::rotr(x, 6) ^ SHA256::rotr(x, 11) ^ SHA256::rotr(x, 25);
}

uint32_t MyCryptoLib::SHA256::rotr(uint32_t value, size_t bits)
{
    return (value >> bits) | (value << ((sizeof(uint32_t) * 8) - bits));
}

uint32_t MyCryptoLib::SHA256::Ch(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (~x & z);
}

uint32_t MyCryptoLib::SHA256::Maj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

