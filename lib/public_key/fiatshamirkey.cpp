#include "fiatshamirkey.h"

bool D35Crypto::FiatShamirKey::isPrivate() const noexcept
{
    return !(p == q && p == 0); // ladno
}

bool D35Crypto::FiatShamirKey::canSign() const noexcept
{
    return isPrivate();
}

bool D35Crypto::FiatShamirKey::canEncrypt() const noexcept
{
    return !isPrivate();
}

bool D35Crypto::FiatShamirKey::canDecrypt() const noexcept
{
    return isPrivate();
}

size_t D35Crypto::FiatShamirKey::blockSize() const
{
    return size(); // idk
}

size_t D35Crypto::FiatShamirKey::size() const
{
    return NTL::NumBytes(this->n);
}

std::vector<uint8_t> D35Crypto::FiatShamirKey::exportPrivateKeyBytes() const
{
    size_t total_a_size = 0;
    for (const NTL::ZZ &ai : this->a)
    {
        total_a_size += NTL::NumBytes(ai);
    }
    std::vector<uint8_t> buffer(8 + 4 + NTL::NumBytes(this->p) + 4 + NTL::NumBytes(this->q) + (4 * this->a.size()) + total_a_size, 0x00);

    buffer[0] = 0x50;
    buffer[1] = 0x52;
    buffer[2] = 0x49;
    buffer[3] = 0x56;
    buffer[4] = 0x4b;
    buffer[5] = 0x45;
    buffer[6] = 0x59;
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

    for (const NTL::ZZ &ai : this->a)
    {
        itemSize = NTL::NumBytes(ai);
        buffer[pos    ] = static_cast<uint8_t>(itemSize >> 24);
        buffer[pos + 1] = static_cast<uint8_t>(itemSize >> 16);
        buffer[pos + 2] = static_cast<uint8_t>(itemSize >> 8 );
        buffer[pos + 3] = static_cast<uint8_t>(itemSize      );
        pos += 4;
        NTL::BytesFromZZ(buffer.data() + pos, ai, itemSize);
        pos += itemSize;
    }

    return buffer;
}

std::vector<uint8_t> D35Crypto::FiatShamirKey::exportPublicKeyBytes() const
{
    size_t total_b_size = 0;
    for (const NTL::ZZ &bi : this->b)
    {
        total_b_size += NTL::NumBytes(bi);
    }
    std::vector<uint8_t> buffer(8 + 4 + NTL::NumBytes(this->n) + (4 * this->b.size()) + total_b_size, 0x00);

    buffer[0] = 0x50;
    buffer[1] = 0x52;
    buffer[2] = 0x49;
    buffer[3] = 0x56;
    buffer[4] = 0x4b;
    buffer[5] = 0x45;
    buffer[6] = 0x59;
    buffer[7] = 0xFF;

    size_t pos = 8;
    size_t itemSize = NTL::NumBytes(this->n);
    buffer[pos    ] = static_cast<uint8_t>(itemSize >> 24);
    buffer[pos + 1] = static_cast<uint8_t>(itemSize >> 16);
    buffer[pos + 2] = static_cast<uint8_t>(itemSize >> 8 );
    buffer[pos + 3] = static_cast<uint8_t>(itemSize      );
    pos += 4;
    NTL::BytesFromZZ(buffer.data() + pos, this->n, itemSize);
    pos += itemSize;

    for (const NTL::ZZ &bi : this->b)
    {
        itemSize = NTL::NumBytes(bi);
        buffer[pos    ] = static_cast<uint8_t>(itemSize >> 24);
        buffer[pos + 1] = static_cast<uint8_t>(itemSize >> 16);
        buffer[pos + 2] = static_cast<uint8_t>(itemSize >> 8 );
        buffer[pos + 3] = static_cast<uint8_t>(itemSize      );
        pos += 4;
        NTL::BytesFromZZ(buffer.data() + pos, bi, itemSize);
        pos += itemSize;
    }

    return buffer;
}

NTL::ZZ D35Crypto::FiatShamirKey::getP() const
{
    if (!this->isPrivate())
    {
        throw D35Crypto::WrongKeyException(__LINE__, __FILE__, "Its not private key");
    }
    return this->p;
}

NTL::ZZ D35Crypto::FiatShamirKey::getQ() const
{
    if (!this->isPrivate())
    {
        throw D35Crypto::WrongKeyException(__LINE__, __FILE__, "Its not private key");
    }
    return this->q;
}

NTL::ZZ D35Crypto::FiatShamirKey::getN() const
{
    return this->n;
}

std::vector<NTL::ZZ> D35Crypto::FiatShamirKey::getA() const
{
    if (!this->isPrivate())
    {
        throw D35Crypto::WrongKeyException(__LINE__, __FILE__, "Its not private key");
    }
    return this->a;
}

std::vector<NTL::ZZ> D35Crypto::FiatShamirKey::getB() const
{
    return this->b;
}
