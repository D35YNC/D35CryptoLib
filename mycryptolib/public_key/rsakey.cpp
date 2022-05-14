#include "rsakey.h"


MyCryptoLib::RSAKey::RSAKey(const PKCS12 &pkcs12Obj)
{
    std::vector<uint8_t> buffer = pkcs12Obj.getField(0);
    this->d = NTL::ZZFromBytes(buffer.data(), buffer.size());

    buffer = pkcs12Obj.getField(1);
    this->p = NTL::ZZFromBytes(buffer.data(), buffer.size());

    buffer = pkcs12Obj.getField(2); // q
    this->q = NTL::ZZFromBytes(buffer.data(), buffer.size());
}

MyCryptoLib::RSAKey::RSAKey(const PKCS8 &pkcs8Obj)
{
    std::vector<uint8_t> buffer = pkcs8Obj.getField(0);
    this->e = NTL::ZZFromBytes(buffer.data(), buffer.size());

    buffer = pkcs8Obj.getField(1);
    this->n = NTL::ZZFromBytes(buffer.data(), buffer.size());
}

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

MyCryptoLib::RSAKey MyCryptoLib::RSAKey::fromPKCS8File(std::string filename)
{
    PKCS8 pkcs(filename);
    return MyCryptoLib::RSAKey::fromPKCS8(pkcs);
}

MyCryptoLib::RSAKey MyCryptoLib::RSAKey::fromPKCS12File(std::string filename)
{
    PKCS12 pkcs(filename);
    return MyCryptoLib::RSAKey::fromPKCS12(pkcs);
}

MyCryptoLib::RSAKey MyCryptoLib::RSAKey::fromPKCS8(const PKCS8 &pkcs8obj)
{
    NTL::ZZ n, e;
    std::vector<uint8_t> buffer = pkcs8obj.getField(0); // n
    NTL::ZZFromBytes(n, buffer.data(), buffer.size());

    buffer = pkcs8obj.getField(1); // e
    NTL::ZZFromBytes(e, buffer.data(), buffer.size());

    return RSAKey(n, e);
}

MyCryptoLib::RSAKey MyCryptoLib::RSAKey::fromPKCS12(const PKCS12 &pkcs12obj)
{
    NTL::ZZ d, p, q;
    std::vector<uint8_t> buffer = pkcs12obj.getField(0); // d
    NTL::ZZFromBytes(d, buffer.data(), buffer.size());

    buffer = pkcs12obj.getField(1); // p
    NTL::ZZFromBytes(p, buffer.data(), buffer.size());

    buffer = pkcs12obj.getField(2); // q
    NTL::ZZFromBytes(q, buffer.data(), buffer.size());

    return RSAKey(p, q, NTL::conv<NTL::ZZ>(65537));
}


//MyCryptoLib::RSAKey MyCryptoLib::RSAKey::fromPKCS8File(std::string filename)
//{
//    std::ifstream pkcs8KeyFile(filename);
//    if (pkcs8KeyFile.is_open())
//    {
//        throw std::runtime_error("Error opening file " + filename);
//    }
//    PKCS8 pkcs8Key(pkcs8KeyFile);
//    return RSAKey(pkcs8Key);
//}

//MyCryptoLib::RSAKey MyCryptoLib::RSAKey::fromPKCS12File(std::string filename)
//{
//    std::ifstream pkcs12KeyFile(filename);
//    if (!pkcs12KeyFile.is_open())
//    {
//        throw std::runtime_error("Error opening file " + filename);
//    }
//    PKCS12 pkcs12Key(pkcs12KeyFile);
//    return RSAKey(pkcs12Key);
//}


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

size_t MyCryptoLib::RSAKey::size() const
{
    return NTL::conv<size_t>(NTL::NumBytes(this->n));
}

MyCryptoLib::PKCS12 MyCryptoLib::RSAKey::exportPrivateKey()
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

    pkcsMap[1] = buffer;

    return PKCS12("RSA", pkcsMap);
}

MyCryptoLib::PKCS8 MyCryptoLib::RSAKey::exportPublicKey()
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

std::vector<uint8_t> MyCryptoLib::RSAKey::exportPrivateKeyBytes()
{
    return this->exportPrivateKey().toBytes();
}

std::vector<uint8_t> MyCryptoLib::RSAKey::exportPublicKeyBytes()
{
    return this->exportPublicKey().toBytes();
}

