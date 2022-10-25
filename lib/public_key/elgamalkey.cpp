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

D35Crypto::ElGamalKey D35Crypto::ElGamalKey::fromPKCS8(PKCS8 *pkcs8obj)
{
    NTL::ZZ p, alpha, beta;

    std::vector<uint8_t> buffer = pkcs8obj->getField(0); // p
    NTL::ZZFromBytes(p, buffer.data(), buffer.size());

    buffer = pkcs8obj->getField(1); // alpha
    NTL::ZZFromBytes(alpha, buffer.data(), buffer.size());

    buffer = pkcs8obj->getField(2); // beta
    NTL::ZZFromBytes(beta, buffer.data(), buffer.size());

    return ElGamalKey(p, alpha, beta);
}

D35Crypto::ElGamalKey D35Crypto::ElGamalKey::fromPKCS12(PKCS12 *pkcs12obj)
{
    NTL::ZZ a, p, alpha;

    std::vector<uint8_t> buffer = pkcs12obj->getField(0); // a
    NTL::ZZFromBytes(a, buffer.data(), buffer.size());
//////
    buffer = pkcs12obj->getField(1); // p
    NTL::ZZFromBytes(p, buffer.data(), buffer.size());

    buffer = pkcs12obj->getField(2); // alpha
    NTL::ZZFromBytes(alpha, buffer.data(), buffer.size());
//////
    return ElGamalKey(a, p, alpha, NTL::conv<NTL::ZZ>(0)); // EXtend privkey for signing
}

D35Crypto::ElGamalKey D35Crypto::ElGamalKey::fromPKCS8File(const std::string &filename)
{
    PKCS8 *pkcs = new PKCS8(filename);
    ElGamalKey r = ElGamalKey::fromPKCS8(pkcs);
    delete pkcs;
    return r;
}

D35Crypto::ElGamalKey D35Crypto::ElGamalKey::fromPKCS12File(const std::string &filename)
{
    PKCS12 *pkcs = new PKCS12(filename);
    ElGamalKey r = ElGamalKey::fromPKCS12(pkcs);
    delete pkcs;
    return r;
}

bool D35Crypto::ElGamalKey::isPrivate() const
{
    return a != 0;
}

bool D35Crypto::ElGamalKey::canSign() const
{
    return this->isPrivate();
}

bool D35Crypto::ElGamalKey::canEncrypt() const
{
    return !this->isPrivate();
}

bool D35Crypto::ElGamalKey::canDecrypt() const
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

D35Crypto::PKCS12 D35Crypto::ElGamalKey::exportPrivateKey() const
{
    std::map<int, std::vector<uint8_t>> pkcsMap;
    std::vector<uint8_t> buffer;

    buffer.resize(NTL::NumBytes(this->a));
    NTL::BytesFromZZ(buffer.data(), this->a, NTL::NumBytes(this->a));
    pkcsMap[0] = buffer;
/////
    buffer.resize(NTL::NumBytes(this->p));
    NTL::BytesFromZZ(buffer.data(), this->p, NTL::NumBytes(this->p));
    pkcsMap[1] = buffer;

    buffer.resize(NTL::NumBytes(this->alpha));
    NTL::BytesFromZZ(buffer.data(), this->alpha, NTL::NumBytes(this->alpha));
    pkcsMap[2] = buffer;
//////
    return PKCS12("ELGAMAL", pkcsMap);
}

D35Crypto::PKCS8 D35Crypto::ElGamalKey::exportPublicKey() const
{
    std::map<int, std::vector<uint8_t>> pkcsMap;
    std::vector<uint8_t> buffer;

    buffer.resize(NTL::NumBytes(this->p));
    NTL::BytesFromZZ(buffer.data(), this->p, NTL::NumBytes(this->p));
    pkcsMap[0] = buffer;

    buffer.resize(NTL::NumBytes(this->alpha));
    NTL::BytesFromZZ(buffer.data(), this->alpha, NTL::NumBytes(this->alpha));
    pkcsMap[1] = buffer;

    buffer.resize(NTL::NumBytes(this->beta));
    NTL::BytesFromZZ(buffer.data(), this->beta, NTL::NumBytes(this->beta));
    pkcsMap[2] = buffer;

    return PKCS8("ELGAMAL", pkcsMap);
}

std::vector<uint8_t> D35Crypto::ElGamalKey::exportPrivateKeyBytes() const
{
    return this->exportPrivateKey().toBytes();
}

std::vector<uint8_t> D35Crypto::ElGamalKey::exportPublicKeyBytes() const
{
    return this->exportPublicKey().toBytes();
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
