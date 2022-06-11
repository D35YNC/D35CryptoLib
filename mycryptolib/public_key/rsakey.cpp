#include "rsakey.h"


MyCryptoLib::RSAKey MyCryptoLib::RSAKey::generate(size_t bitSize)
{
    NTL::ZZ n;
    NTL::ZZ e = NTL::conv<NTL::ZZ>(65537);
    NTL::ZZ p;
    NTL::ZZ q;
    NTL::ZZ d;

    if (bitSize % 2048 != 0)
    {
        throw std::invalid_argument("Invalid key size");
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

MyCryptoLib::RSAKey MyCryptoLib::RSAKey::fromPKCS8File(const std::string &filename)
{
    PKCS8 *pkcs = new PKCS8(filename);
    RSAKey r = RSAKey::fromPKCS8(pkcs);
    delete pkcs;
    return r;
}

MyCryptoLib::RSAKey MyCryptoLib::RSAKey::fromPKCS12File(const std::string &filename)
{
    PKCS12 *pkcs = new PKCS12(filename);
    RSAKey r = RSAKey::fromPKCS12(pkcs);
    delete pkcs;
    return r;
}

MyCryptoLib::RSAKey MyCryptoLib::RSAKey::fromPKCS8(PKCS8 *pkcs8obj)
{
    NTL::ZZ n, e;

    std::vector<uint8_t> buffer = pkcs8obj->getField(0); // e
    NTL::ZZFromBytes(e, buffer.data(), buffer.size());

    buffer = pkcs8obj->getField(1); // n
    NTL::ZZFromBytes(n, buffer.data(), buffer.size());

    return RSAKey(n, e);
}

MyCryptoLib::RSAKey MyCryptoLib::RSAKey::fromPKCS12(PKCS12 *pkcs12obj)
{
    NTL::ZZ d, p, q;
    std::vector<uint8_t> buffer = pkcs12obj->getField(0); // p
    NTL::ZZFromBytes(p, buffer.data(), buffer.size());

    buffer = pkcs12obj->getField(1); // q
    NTL::ZZFromBytes(q, buffer.data(), buffer.size());

    buffer = pkcs12obj->getField(2); // d
    NTL::ZZFromBytes(d, buffer.data(), buffer.size());

    return RSAKey(p, q, NTL::conv<NTL::ZZ>(65537));
}


NTL::ZZ MyCryptoLib::RSAKey::getModulus() const
{
    return this->n;
}

NTL::ZZ MyCryptoLib::RSAKey::getPublicExponent() const
{
    return this->e;
}

NTL::ZZ MyCryptoLib::RSAKey::getPrivateExponent() const
{
    if (this->isPrivate())
    {
        return this->d;
    }
    else
    {
        throw MyCryptoLib::WrongKeyException("Public key not contains private exponent d");
    }
}

bool MyCryptoLib::RSAKey::isPrivate() const
{
    return (p != 0) && (q != 0) && (d != 0);
}

bool MyCryptoLib::RSAKey::canEncrypt() const
{
    return (n != 0) && (e != 0);
}

bool MyCryptoLib::RSAKey::canDecrypt() const
{
    return isPrivate();
}

size_t MyCryptoLib::RSAKey::blockSize() const
{
    return static_cast<size_t>(this->size() / 2);
}

size_t MyCryptoLib::RSAKey::size() const
{
    return NTL::conv<size_t>(NTL::NumBytes(this->n));
}

MyCryptoLib::PKCS12 MyCryptoLib::RSAKey::exportPrivateKey() const
{
    std::map<int, std::vector<uint8_t>> pkcsMap;

    std::vector<uint8_t> buffer;

    buffer.resize(NTL::NumBytes(this->p));
    NTL::BytesFromZZ(buffer.data(), this->p, NTL::NumBytes(this->p));
    pkcsMap[0] = buffer;

    buffer.resize(NTL::NumBytes(this->q));
    NTL::BytesFromZZ(buffer.data(), this->q, NTL::NumBytes(this->q));
    pkcsMap[1] = buffer;

    buffer.resize(NTL::NumBytes(this->d));
    NTL::BytesFromZZ(buffer.data(), this->d, NTL::NumBytes(this->d));
    pkcsMap[2] = buffer;

    return PKCS12("RSA", pkcsMap);
}

MyCryptoLib::PKCS8 MyCryptoLib::RSAKey::exportPublicKey() const
{
    std::map<int, std::vector<uint8_t>> pkcsMap;

    std::vector<uint8_t> buffer;

    buffer.resize(NTL::NumBytes(this->e));
    NTL::BytesFromZZ(buffer.data(), this->e, NTL::NumBytes(this->e));
    pkcsMap[0] = buffer;

    buffer.resize(NTL::NumBytes(this->n));
    NTL::BytesFromZZ(buffer.data(), this->n, NTL::NumBytes(this->n));
    pkcsMap[1] = buffer;

    return PKCS8("RSA", pkcsMap);
}

std::vector<uint8_t> MyCryptoLib::RSAKey::exportPrivateKeyBytes() const
{
    return this->exportPrivateKey().toBytes();
}

std::vector<uint8_t> MyCryptoLib::RSAKey::exportPublicKeyBytes() const
{
    return this->exportPublicKey().toBytes();
}

