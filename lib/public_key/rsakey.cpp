#include "rsakey.h"


D35Crypto::RSAKey D35Crypto::RSAKey::generate(size_t bitSize)
{
    NTL::ZZ n;
    NTL::ZZ e = NTL::conv<NTL::ZZ>(65537);
    NTL::ZZ p;
    NTL::ZZ q;
    NTL::ZZ d;

    if (bitSize % 2048 != 0)
    {
        throw D35Crypto::BadKeySizeException(__LINE__, __FILE__);
    }

    // Generating 512 bytes seed
    std::vector<unsigned char> seed(512, 0x00);
    std::uniform_int_distribution<uint64_t> dist(0, UINT64_MAX - 1);
    std::random_device dev_random("/dev/random");
    for (int i = 0; i < seed.size(); i++)
    {
        seed[i] = dist(dev_random);
    }
    NTL::SetSeed(seed.data(), seed.size());

    p = NTL::GenPrime_ZZ(static_cast<long>(bitSize / 2));
    q = NTL::GenPrime_ZZ(static_cast<long>(bitSize / 2));
    n = p * q;

    NTL::ZZ phi = (p - 1) * (q - 1);
    d = NTL::InvMod(e % phi, phi);

    return RSAKey(n, e, p, q, d);
}

D35Crypto::RSAKey D35Crypto::RSAKey::publicKeyFromBytes(const std::vector<uint8_t> &buffer, bool skipHeaders)
{
    size_t pos = skipHeaders ? 8 : 0;
    uint32_t itemSize = 0;
    std::vector<uint8_t> tmp;
    NTL::ZZ e;
    NTL::ZZ n;


    itemSize = (buffer[pos] << 24) | (buffer[pos + 1] << 16) | (buffer[pos + 2] << 8) | (buffer[pos + 3]);
    pos += 4;
    tmp.resize(itemSize);
    std::copy(buffer.begin() + pos, buffer.begin() + pos + itemSize, tmp.begin());
    NTL::ZZFromBytes(e, buffer.data(), buffer.size());
    pos += itemSize;

    itemSize = (buffer[pos] << 24) | (buffer[pos + 1] << 16) | (buffer[pos + 2] << 8) | (buffer[pos + 3]);
    pos += 4;
    tmp.resize(itemSize);
    std::copy(buffer.begin() + pos, buffer.begin() + pos + itemSize, tmp.begin());
    NTL::ZZFromBytes(n, buffer.data(), buffer.size());

    return RSAKey(n, e);
}

D35Crypto::RSAKey D35Crypto::RSAKey::privateKeyFromBytes(const std::vector<uint8_t> &buffer, bool skipHeaders)
{
    size_t pos = skipHeaders ? 8 : 0;
    uint32_t itemSize = 0;
    std::vector<uint8_t> tmp;
    NTL::ZZ p;
    NTL::ZZ q;
    NTL::ZZ e;
    NTL::ZZ d;

    itemSize = (buffer[pos] << 24) | (buffer[pos + 1] << 16) | (buffer[pos + 2] << 8) | (buffer[pos + 3]);
    pos += 4;
    tmp.resize(itemSize);
    std::copy(buffer.begin() + pos, buffer.begin() + pos + itemSize, tmp.begin());
    NTL::ZZFromBytes(p, buffer.data(), buffer.size());
    pos += itemSize;

    itemSize = (buffer[pos] << 24) | (buffer[pos + 1] << 16) | (buffer[pos + 2] << 8) | (buffer[pos + 3]);
    pos += 4;
    tmp.resize(itemSize);
    std::copy(buffer.begin() + pos, buffer.begin() + pos + itemSize, tmp.begin());
    NTL::ZZFromBytes(q, buffer.data(), buffer.size());
    pos += itemSize;

    itemSize = (buffer[pos] << 24) | (buffer[pos + 1] << 16) | (buffer[pos + 2] << 8) | (buffer[pos + 3]);
    pos += 4;
    tmp.resize(itemSize);
    std::copy(buffer.begin() + pos, buffer.begin() + pos + itemSize, tmp.begin());
    NTL::ZZFromBytes(e, buffer.data(), buffer.size());
    pos += itemSize;

    itemSize = (buffer[pos] << 24) | (buffer[pos + 1] << 16) | (buffer[pos + 2] << 8) | (buffer[pos + 3]);
    pos += 4;
    tmp.resize(itemSize);
    std::copy(buffer.begin() + pos, buffer.begin() + pos + itemSize, tmp.begin());
    NTL::ZZFromBytes(d, buffer.data(), buffer.size());
//    pos += itemSize;

    return RSAKey(p, q, e, d);
}

NTL::ZZ D35Crypto::RSAKey::getModulus() const noexcept
{
    return this->n;
}

NTL::ZZ D35Crypto::RSAKey::getPublicExponent() const noexcept
{
    return this->e;
}

NTL::ZZ D35Crypto::RSAKey::getPrivateExponent() const
{
    if (this->isPrivate())
    {
        return this->d;
    }
    else
    {
        throw D35Crypto::WrongKeyException(__LINE__, __FILE__, "The public key does not contain a private exponent d");
    }
}

bool D35Crypto::RSAKey::isPrivate() const noexcept
{
    return (p != 0) && (q != 0) && (d != 0);
}

bool D35Crypto::RSAKey::canSign() const noexcept
{
    return isPrivate();
}

bool D35Crypto::RSAKey::canEncrypt() const noexcept
{
    return (n != 0) && (e != 0);
}

bool D35Crypto::RSAKey::canDecrypt() const noexcept
{
    return isPrivate();
}

size_t D35Crypto::RSAKey::blockSize() const
{
    return static_cast<size_t>(this->size() / 2);
}

size_t D35Crypto::RSAKey::size() const
{
    return NTL::conv<size_t>(NTL::NumBytes(this->n));
}

std::vector<uint8_t> D35Crypto::RSAKey::exportPrivateKeyBytes() const
{
    std::vector<uint8_t> buffer(8 + 4 + NTL::NumBytes(this->p) + 4 + NTL::NumBytes(this->q) + 4 + NTL::NumBytes(this->e) + 4 + NTL::NumBytes(this->d), 0x00);

    buffer[0] = 0x50;
    buffer[1] = 0x55;
    buffer[2] = 0x42;
    buffer[3] = 0x4b;
    buffer[4] = 0x45;
    buffer[5] = 0x59;
    buffer[6] = 0xFF;
    buffer[7] = 0xFF;

    size_t pos = 8;
    size_t itemSize = NTL::NumBytes(this->p);
    buffer[pos    ] = static_cast<uint8_t>(itemSize >> 24);
    buffer[pos + 1] = static_cast<uint8_t>(itemSize >> 16);
    buffer[pos + 2] = static_cast<uint8_t>(itemSize >> 8 );
    buffer[pos + 3] = static_cast<uint8_t>(itemSize      );
    pos += 4;
    NTL::BytesFromZZ(buffer.data() + pos, this->p, itemSize);
    pos += itemSize;

    itemSize = NTL::NumBytes(this->q);
    buffer[pos    ] = static_cast<uint8_t>(itemSize >> 24);
    buffer[pos + 1] = static_cast<uint8_t>(itemSize >> 16);
    buffer[pos + 2] = static_cast<uint8_t>(itemSize >> 8 );
    buffer[pos + 3] = static_cast<uint8_t>(itemSize      );
    pos += 4;
    NTL::BytesFromZZ(buffer.data() + pos, this->q, itemSize);
    pos += itemSize;

    itemSize = NTL::NumBytes(this->e);
    buffer[pos    ] = static_cast<uint8_t>(itemSize >> 24);
    buffer[pos + 1] = static_cast<uint8_t>(itemSize >> 16);
    buffer[pos + 2] = static_cast<uint8_t>(itemSize >> 8 );
    buffer[pos + 3] = static_cast<uint8_t>(itemSize      );
    pos += 4;
    NTL::BytesFromZZ(buffer.data() + pos, this->e, itemSize);
    pos += itemSize;

    itemSize = NTL::NumBytes(this->d);
    buffer[pos    ] = static_cast<uint8_t>(itemSize >> 24);
    buffer[pos + 1] = static_cast<uint8_t>(itemSize >> 16);
    buffer[pos + 2] = static_cast<uint8_t>(itemSize >> 8 );
    buffer[pos + 3] = static_cast<uint8_t>(itemSize      );
    pos += 4;
    NTL::BytesFromZZ(buffer.data() + pos, this->d, itemSize);
//    pos += itemSize;

    return buffer;
}

std::vector<uint8_t> D35Crypto::RSAKey::exportPublicKeyBytes() const
{
    std::vector<uint8_t> buffer(8 + 4 + NTL::NumBytes(this->e) + 4 + NTL::NumBytes(this->n), 0x00);

    buffer[0] = 0x50;
    buffer[1] = 0x52;
    buffer[2] = 0x49;
    buffer[3] = 0x56;
    buffer[4] = 0x4b;
    buffer[5] = 0x45;
    buffer[6] = 0x59;
    buffer[7] = 0xFF;

    size_t pos = 8;
    size_t itemSize = NTL::NumBytes(this->e);
    buffer[pos    ] = static_cast<uint8_t>(itemSize >> 24);
    buffer[pos + 1] = static_cast<uint8_t>(itemSize >> 16);
    buffer[pos + 2] = static_cast<uint8_t>(itemSize >> 8 );
    buffer[pos + 3] = static_cast<uint8_t>(itemSize      );
    pos += 4;
    NTL::BytesFromZZ(buffer.data() + pos, this->e, itemSize);
    pos += itemSize;

    itemSize = NTL::NumBytes(this->n);
    buffer[pos    ] = static_cast<uint8_t>(itemSize >> 24);
    buffer[pos + 1] = static_cast<uint8_t>(itemSize >> 16);
    buffer[pos + 2] = static_cast<uint8_t>(itemSize >> 8 );
    buffer[pos + 3] = static_cast<uint8_t>(itemSize      );
    pos += 4;
    NTL::BytesFromZZ(buffer.data() + pos, this->n, itemSize);
//    pos += itemSize;

    return buffer;
}
