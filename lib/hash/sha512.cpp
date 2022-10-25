#include "sha512.h"

void D35Crypto::SHA512::_init()
{
    this->_hashState[0] = 0x6a09e667f3bcc908;
    this->_hashState[1] = 0xbb67ae8584caa73b;
    this->_hashState[2] = 0x3c6ef372fe94f82b;
    this->_hashState[3] = 0xa54ff53a5f1d36f1;
    this->_hashState[4] = 0x510e527fade682d1;
    this->_hashState[5] = 0x9b05688c2b3e6c1f;
    this->_hashState[6] = 0x1f83d9abfb41bd6b;
    this->_hashState[7] = 0x5be0cd19137e2179;
}

void D35Crypto::SHA512::update(const std::string &data)
{
    this->update(std::vector<uint8_t>(data.begin(), data.end()));
}

void D35Crypto::SHA512::update(const std::vector<uint8_t> &data)
{
    std::vector<uint8_t> buffer = data;
    this->_init();
    this->_pad(buffer, data.size());
    this->_updateState(buffer);
    this->_finalize();
}

void D35Crypto::SHA512::update(std::ifstream &file)
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

    //process first I full blocks
    std::vector<uint8_t> readBuffer(4096);
    for (int i = 0; i < static_cast<int>(fileSize / 4096); i++)
    {
        file.read(reinterpret_cast<char*>(readBuffer.data()), readBuffer.size());
        this->_updateState(readBuffer);
    }

    //process last block wth padding
    int lastBlockSize = (int)(fileSize % 4096);
    readBuffer.resize(lastBlockSize);
    file.read((char*)readBuffer.data(), readBuffer.size());

    this->_pad(readBuffer, fileSize);
    this->_updateState(readBuffer);
    this->_finalize();
}

size_t D35Crypto::SHA512::blockSize()
{
    return 128;
}

void D35Crypto::SHA512::_updateState(const std::vector<uint8_t> &buffer)
{
    int pos = 0;
    while (pos < buffer.size())
    {
        std::vector<uint64_t> block(80);
        for (int i = 0; i < 16; i++)
        {
            block[i] =  (((uint64_t)(buffer[pos]) << 56) |
                        ((uint64_t)(buffer[pos + 1]) << 48) |
                        ((uint64_t)(buffer[pos + 2]) << 40) |
                        ((uint64_t)(buffer[pos + 3]) << 32) |
                        ((uint64_t)(buffer[pos + 4]) << 24) |
                        ((uint64_t)(buffer[pos + 5]) << 16) |
                        ((uint64_t)(buffer[pos + 6]) << 8) |
                        ((uint64_t)(buffer[pos + 7])));
            pos += 8;
        }
        this->_processBlock(block);
    }
}

void D35Crypto::SHA512::_processBlock(std::vector<uint64_t> block)
{
    for (int i = 16; i < 80; i++)
    {
        block[i] = block[i - 16] +
                SHA512::Sigma0(block[i - 15]) +
                block[i-7] +
                SHA512::Sigma1(block[i - 2]);
    }

    // Мб в масисв это все засунуть

    uint64_t a = _hashState[0];
    uint64_t b = _hashState[1];
    uint64_t c = _hashState[2];
    uint64_t d = _hashState[3];
    uint64_t e = _hashState[4];
    uint64_t f = _hashState[5];
    uint64_t g = _hashState[6];
    uint64_t h = _hashState[7];

    for (int i = 0; i < 80; i++)
    {
        uint64_t t1 = h + SHA512::SIGMA1(e) + SHA512::Ch(e, f, g) + SHA512::CONSTS[i] + block[i];
        uint64_t t2 = SHA512::SIGMA0(a) + SHA512::Maj(a, b, c);

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

void D35Crypto::SHA512::_pad(std::vector<uint8_t> &buffer, size_t dataSize)
{
    uint64_t bitSize = dataSize * 8;
    int k = (896 - 1 - bitSize) % 1024; // zeroes bits scount

    // fill '1' & k '0' // count in bytes
    buffer.push_back(0x80); // '1' & 7 zeroes
    for (int i = 1; i < static_cast<int>((k + 1) / 8); i++)
    {
        buffer.push_back(0x00); // 8 zeroes
    }

    // 64
    for (int i = 0; i < 8; i++)
    {
        buffer.push_back(0x00);
    }
    // +64
    buffer.push_back((uint8_t)(bitSize >> 56));
    buffer.push_back((uint8_t)(bitSize >> 48));
    buffer.push_back((uint8_t)(bitSize >> 40));
    buffer.push_back((uint8_t)(bitSize >> 32));
    buffer.push_back((uint8_t)(bitSize >> 24));
    buffer.push_back((uint8_t)(bitSize >> 16));
    buffer.push_back((uint8_t)(bitSize >> 8));
    buffer.push_back((uint8_t)(bitSize));
}

void D35Crypto::SHA512::_finalize()
{
    for (int i = 0; i < 8; i++)
    {
        this->_digest[i * 8] = (uint8_t)(_hashState[i] >> 56);
        this->_digest[(i * 8) + 1] = (uint8_t)(_hashState[i] >> 48);
        this->_digest[(i * 8) + 2] = (uint8_t)(_hashState[i] >> 40);
        this->_digest[(i * 8) + 3] = (uint8_t)(_hashState[i] >> 32);
        this->_digest[(i * 8) + 4] = (uint8_t)(_hashState[i] >> 24);
        this->_digest[(i * 8) + 5] = (uint8_t)(_hashState[i] >> 16);
        this->_digest[(i * 8) + 6] = (uint8_t)(_hashState[i] >> 8);
        this->_digest[(i * 8) + 7] = (uint8_t)(_hashState[i]);
    }
}


uint64_t D35Crypto::SHA512::Sigma0(uint64_t x)
{
    return SHA512::rotr(x, 1) ^ SHA512::rotr(x, 8) ^ (x >> 7);
}

uint64_t D35Crypto::SHA512::Sigma1(uint64_t x)
{
    return SHA512::rotr(x, 19) ^ SHA512::rotr(x, 61) ^ (x >> 6);
}

uint64_t D35Crypto::SHA512::SIGMA0(uint64_t x)
{
    return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39);
}

uint64_t D35Crypto::SHA512::SIGMA1(uint64_t x)
{
    return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41);
}

uint64_t D35Crypto::SHA512::rotr(uint64_t value, size_t bits)
{
    return (value >> bits) | (value << ((sizeof(uint64_t) * 8) - bits));
}

uint64_t D35Crypto::SHA512::Ch(uint64_t x, uint64_t y, uint64_t z)
{
    return (x & y) ^ (~x & z);
}

uint64_t D35Crypto::SHA512::Maj(uint64_t x, uint64_t y, uint64_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}
