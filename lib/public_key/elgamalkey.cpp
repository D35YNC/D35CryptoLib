#include "elgamalkey.h"


D35Crypto::ElGamalKey D35Crypto::ElGamalKey::generate(size_t bitSize)
{
    std::vector<unsigned char> seed(512, 0x00);
    std::uniform_int_distribution<uint64_t> dist(0, UINT64_MAX - 1);
    std::random_device dev_random("/dev/random");
    for (int i = 0; i < seed.size(); i++)
    {
        seed[i] = dist(dev_random);
    }
    NTL::SetSeed(seed.data(), seed.size());

    NTL::ZZ p;
    NTL::ZZ alpha;
    NTL::ZZ beta;
    NTL::ZZ a;

    p = NTL::GenPrime_ZZ(bitSize); // Просто простое
    while (true)
    {
        alpha = NTL::RandomBnd(p); // обрй элт грпы

        if (NTL::PowerMod(alpha, p - 1, p) == NTL::conv<NTL::ZZ>(1))
        {
            break;
        }
    }
    // old
//    while (NTL::ProbPrime(p, 100) == 0)
//    {
//        alpha = NTL::GenGermainPrime_ZZ(static_cast<long>(bitSize));
//        p = (2 * alpha) + 1;
//        phi = p - 1;
//    }

    a = NTL::RandomBnd(p - 1) + 1; // random [1, p-2]
    beta = NTL::PowerMod(alpha, a, p);

    if (NTL::conv<int>(NTL::PowerMod(a, p - 1, p)) != 1)
    {
        throw std::exception(); // Что то пошло не так. ХЗ как выбирать альфу. по идее так
    }

    return ElGamalKey(a, p, alpha, beta);
}

bool D35Crypto::ElGamalKey::isPrivate() const noexcept
{
    return a != 0;
}

bool D35Crypto::ElGamalKey::canSign() const noexcept
{
    return this->isPrivate();
}

bool D35Crypto::ElGamalKey::canEncrypt() const noexcept
{
    return !this->isPrivate();
}

bool D35Crypto::ElGamalKey::canDecrypt() const noexcept
{
    return this->isPrivate();
}

size_t D35Crypto::ElGamalKey::blockSize() const
{
    return NTL::NumBytes(this->p);
}

size_t D35Crypto::ElGamalKey::size() const
{
    return NTL::NumBytes(this->p);
}

std::vector<uint8_t> D35Crypto::ElGamalKey::exportPrivateKeyBytes() const
{
    std::vector<uint8_t> buffer(8 + 4 + NTL::NumBytes(this->a) + 4 + NTL::NumBytes(this->p) + 4 + NTL::NumBytes(this->alpha), 0x00);

    buffer[0] = 0x50;
    buffer[1] = 0x55;
    buffer[2] = 0x42;
    buffer[3] = 0x4b;
    buffer[4] = 0x45;
    buffer[5] = 0x59;
    buffer[6] = 0xFF;
    buffer[7] = 0xFF;

    size_t pos = 8;
    size_t itemSize = NTL::NumBytes(this->a);
    buffer[pos    ] = static_cast<uint8_t>(itemSize >> 24);
    buffer[pos + 1] = static_cast<uint8_t>(itemSize >> 16);
    buffer[pos + 2] = static_cast<uint8_t>(itemSize >> 8 );
    buffer[pos + 3] = static_cast<uint8_t>(itemSize      );
    pos += 4;
    NTL::BytesFromZZ(buffer.data() + pos, this->a, itemSize);
    pos += itemSize;

    itemSize = NTL::NumBytes(this->p);
    buffer[pos    ] = static_cast<uint8_t>(itemSize >> 24);
    buffer[pos + 1] = static_cast<uint8_t>(itemSize >> 16);
    buffer[pos + 2] = static_cast<uint8_t>(itemSize >> 8 );
    buffer[pos + 3] = static_cast<uint8_t>(itemSize      );
    pos += 4;
    NTL::BytesFromZZ(buffer.data() + pos, this->p, itemSize);
    pos += itemSize;

    itemSize = NTL::NumBytes(this->alpha);
    buffer[pos    ] = static_cast<uint8_t>(itemSize >> 24);
    buffer[pos + 1] = static_cast<uint8_t>(itemSize >> 16);
    buffer[pos + 2] = static_cast<uint8_t>(itemSize >> 8 );
    buffer[pos + 3] = static_cast<uint8_t>(itemSize      );
    pos += 4;
    NTL::BytesFromZZ(buffer.data() + pos, this->alpha, itemSize);
//    pos += itemSize;

    return buffer;
}

std::vector<uint8_t> D35Crypto::ElGamalKey::exportPublicKeyBytes() const
{
    std::vector<uint8_t> buffer(8 + 4 + NTL::NumBytes(this->p) + 4 + NTL::NumBytes(this->alpha) + 4 + NTL::NumBytes(this->beta), 0x00);

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

    itemSize = NTL::NumBytes(this->alpha);
    buffer[pos    ] = static_cast<uint8_t>(itemSize >> 24);
    buffer[pos + 1] = static_cast<uint8_t>(itemSize >> 16);
    buffer[pos + 2] = static_cast<uint8_t>(itemSize >> 8 );
    buffer[pos + 3] = static_cast<uint8_t>(itemSize      );
    pos += 4;
    NTL::BytesFromZZ(buffer.data() + pos, this->alpha, itemSize);
    pos += itemSize;

    itemSize = NTL::NumBytes(this->beta);
    buffer[pos    ] = static_cast<uint8_t>(itemSize >> 24);
    buffer[pos + 1] = static_cast<uint8_t>(itemSize >> 16);
    buffer[pos + 2] = static_cast<uint8_t>(itemSize >> 8 );
    buffer[pos + 3] = static_cast<uint8_t>(itemSize      );
    pos += 4;
    NTL::BytesFromZZ(buffer.data() + pos, this->beta, itemSize);
//    pos += itemSize;

    return buffer;
}

NTL::ZZ D35Crypto::ElGamalKey::getAlpha() const
{
    return this->alpha;
}

NTL::ZZ D35Crypto::ElGamalKey::getBeta() const
{
    return this->beta;
}

NTL::ZZ D35Crypto::ElGamalKey::getP() const
{
    return this->p;
}

NTL::ZZ D35Crypto::ElGamalKey::getA() const
{
    return this->a;
}
