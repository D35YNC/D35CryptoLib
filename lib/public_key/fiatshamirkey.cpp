#include "fiatshamirkey.h"

D35Crypto::FiatShamirKey D35Crypto::FiatShamirKey::generate(size_t bitSize, HashBase *hash)
{
    NTL::ZZ p;
    NTL::ZZ q;
    NTL::ZZ n;
    NTL::ZZ tmp = NTL::conv<NTL::ZZ>(0);
    size_t i_count = hash->digestSize() * 8;
    std::vector<NTL::ZZ> a(i_count);
    std::vector<NTL::ZZ> b(i_count);

    if (bitSize % 1024 != 0)
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

    // random pq
    p = NTL::GenPrime_ZZ(static_cast<long>(bitSize / 2));
    q = NTL::GenPrime_ZZ(static_cast<long>(bitSize / 2));
    n = p * q;

    for (int i = 0; i < i_count; i++)
    {
        do
        {
            tmp = NTL::RandomBnd(n); // random A[i]. GCD(a, n) == 1
        } while (NTL::GCD(tmp, n) != NTL::conv<NTL::ZZ>(1));
        a[i] = tmp;
    }

    for (int i = 0; i < i_count; i++)
    {
        tmp = NTL::PowerMod(NTL::InvMod(a[i], n), 2, n); // b[i] = (a[i]^-1) ^ 2 mod n
        b[i] = tmp;
    }

    return D35Crypto::FiatShamirKey(p, q, n, a, b, hash);
}

D35Crypto::FiatShamirKey D35Crypto::FiatShamirKey::fromPKCS8(PKCS8 *pkcs8obj)
{
    std::vector<uint8_t> buf = pkcs8obj->getField(0);

    std::string hashId = std::string(buf.begin(), buf.end());

    buf = pkcs8obj->getField(1);
    NTL::ZZ n = NTL::ZZFromBytes(buf.data(), buf.size());

    HashBase *hash = nullptr;
    if (hashId == "SHA256")
    {
        hash = new D35Crypto::SHA256();
    }
    else if (hashId == "SHA512")
    {
        hash = new D35Crypto::SHA512();
    }
    else if (hashId == "Streebog256")
    {
        D35Crypto::Streebog *s = new D35Crypto::Streebog();
        s->setMode(512);
        hash = s;
    }
    else if (hashId == "Streebog512")
    {
        D35Crypto::Streebog *s = new D35Crypto::Streebog();
        s->setMode(256);
        hash = s;
    }
    else
    {
        throw std::runtime_error("iunknown cipher");
    }
    std::vector<NTL::ZZ> b(hash->digestSize() * 8);
    for (int i = 0; i < b.size(); i++)
    {
        buf = pkcs8obj->getField(i + 2);
        b[i] = NTL::ZZFromBytes(buf.data(), buf.size());
    }
    return D35Crypto::FiatShamirKey(n, b, hash);
}

D35Crypto::FiatShamirKey D35Crypto::FiatShamirKey::fromPKCS12(PKCS12 *pkcs12obj)
{
    std::vector<uint8_t> buf = pkcs12obj->getField(0);

    std::string hashId = std::string(buf.begin(), buf.end());

    buf = pkcs12obj->getField(1);
    NTL::ZZ p = NTL::ZZFromBytes(buf.data(), buf.size());

    buf = pkcs12obj->getField(2);
    NTL::ZZ q = NTL::ZZFromBytes(buf.data(), buf.size());

    HashBase *hash = nullptr;
    if (hashId == "SHA256")
    {
        hash = new D35Crypto::SHA256();
    }
    else if (hashId == "SHA512")
    {
        hash = new D35Crypto::SHA512();
    }
    else if (hashId == "Streebog256")
    {
        D35Crypto::Streebog *s = new D35Crypto::Streebog();
        s->setMode(512);
        hash = s;
    }
    else if (hashId == "Streebog512")
    {
        D35Crypto::Streebog *s = new D35Crypto::Streebog();
        s->setMode(256);
        hash = s;
    }
    else
    {
        throw std::runtime_error("iunknown cipher");
    }

    std::vector<NTL::ZZ> a(hash->digestSize() * 8);
    for (int i = 0; i < a.size(); i++)
    {
        buf = pkcs12obj->getField(i + 3);
        a[i] = NTL::ZZFromBytes(buf.data(), buf.size());
    }
    return D35Crypto::FiatShamirKey(p, q, a, hash);
}

D35Crypto::FiatShamirKey D35Crypto::FiatShamirKey::fromPKCS8File(const std::string &filename)
{
    PKCS8 *pkcs = new PKCS8(filename);
    FiatShamirKey r = FiatShamirKey::fromPKCS8(pkcs);
    delete pkcs;
    return r;
}

D35Crypto::FiatShamirKey D35Crypto::FiatShamirKey::fromPKCS12File(const std::string &filename)
{
    PKCS12 *pkcs = new PKCS12(filename);
    FiatShamirKey r = FiatShamirKey::fromPKCS12(pkcs);
    delete pkcs;
    return r;
}

bool D35Crypto::FiatShamirKey::isPrivate() const
{
    return !(p == q && p == 0); // ladno
}

bool D35Crypto::FiatShamirKey::canSign() const
{
    return isPrivate();
}

bool D35Crypto::FiatShamirKey::canEncrypt() const
{
    return !isPrivate();
}

bool D35Crypto::FiatShamirKey::canDecrypt() const
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

D35Crypto::PKCS12 D35Crypto::FiatShamirKey::exportPrivateKey() const
{
    std::map<int, std::vector<uint8_t>> keyMap;
    std::vector<uint8_t> buffer;

    keyMap[0] = std::vector<uint8_t>(this->hashId.begin(), this->hashId.end());

    buffer.resize(NTL::NumBytes(this->p));
    NTL::BytesFromZZ(buffer.data(), this->p, NTL::NumBytes(this->p));
    keyMap[1] = buffer;

    buffer.resize(NTL::NumBytes(this->q));
    NTL::BytesFromZZ(buffer.data(), this->q, NTL::NumBytes(this->q));
    keyMap[2] = buffer;

    for (int i = 0; i < this->a.size(); i++)
    {
        buffer.resize(NTL::NumBytes(this->a[i]));
        NTL::BytesFromZZ(buffer.data(), this->a[i], NTL::NumBytes(this->a[i]));
        keyMap[i + 3] = buffer;
    }

    return PKCS12("FIATSHAMIR", keyMap);
}

D35Crypto::PKCS8 D35Crypto::FiatShamirKey::exportPublicKey() const
{
    std::map<int, std::vector<uint8_t>> keyMap;
    std::vector<uint8_t> buffer;

    keyMap[0] = std::vector<uint8_t>(this->hashId.begin(), this->hashId.end());

    buffer.resize(NTL::NumBytes(this->n));
    NTL::BytesFromZZ(buffer.data(), this->n, NTL::NumBytes(this->n));
    keyMap[1] = buffer;

    for (int i = 0; i < this->b.size(); i++)
    {
        buffer.resize(NTL::NumBytes(this->b[i]));
        NTL::BytesFromZZ(buffer.data(), this->b[i], NTL::NumBytes(this->b[i]));
        keyMap[i + 2] = buffer;
    }
    return PKCS8("FIATSHAMIR", keyMap);
}

std::vector<uint8_t> D35Crypto::FiatShamirKey::exportPrivateKeyBytes() const
{
    return this->exportPrivateKey().toBytes();
}

std::vector<uint8_t> D35Crypto::FiatShamirKey::exportPublicKeyBytes() const
{
    return this->exportPublicKey().toBytes();
}

NTL::ZZ D35Crypto::FiatShamirKey::getP() const
{
    if (!this->isPrivate())
    {
        throw std::runtime_error("is not privkey");
    }
    return this->p;
}

NTL::ZZ D35Crypto::FiatShamirKey::getQ() const
{
    if (!this->isPrivate())
    {
        throw std::runtime_error("is not privkey");
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
        throw std::runtime_error("is not privkey");
    }
    return this->a;
}

std::vector<NTL::ZZ> D35Crypto::FiatShamirKey::getB() const
{
    return this->b;
}

std::string D35Crypto::FiatShamirKey::getHashId() const
{
    return this->hashId;
}
