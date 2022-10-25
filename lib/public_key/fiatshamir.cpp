#include "fiatshamir.h"
#include "../utils.h"


D35Crypto::CAdES D35Crypto::FiatShamir::sign(const std::string &username, const std::vector<uint8_t> &pubKeyHash, const std::string &data,  D35Crypto::HashBase *hash, const FiatShamirKey &key)
{
    return D35Crypto::FiatShamir::sign(username, pubKeyHash, "TEXT", std::vector<uint8_t>(data.begin(), data.end()), hash, key);
}

D35Crypto::CAdES D35Crypto::FiatShamir::sign(const std::string &username, const std::vector<uint8_t> &pubKeyHash, const std::string &contentType, const std::vector<uint8_t> &data, D35Crypto::HashBase *hash, const FiatShamirKey &key)
{
    if (hash->name() != key.getHashId())
    {
        throw std::runtime_error("wrong hashes error");
    }

    hash->update(data);
    std::vector<uint8_t> dataHash = hash->digest();
    std::vector<uint8_t> signature;

    sign(signature, data, key.getN(), key.getA(), hash);

    return D35Crypto::CAdES::create(1, contentType, username, pubKeyHash, hash->name(), "Fiat-Shamir", dataHash, signature);
}

D35Crypto::CAdES D35Crypto::FiatShamir::sign(const std::string &username, const std::vector<uint8_t> &pubKeyHash, const std::string &contentType, const std::string &filename, D35Crypto::HashBase *hash, const FiatShamirKey &key)
{
    if (hash->name() != key.getHashId())
    {
        throw std::runtime_error("wrong hashes error");
    }

    NTL::ZZ n = key.getN();
    NTL::ZZ r = NTL::RandomBnd(n - 1) + 1;
    NTL::ZZ u = NTL::PowerMod(r, 2, n);

    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open())
    {
        throw std::runtime_error("ioseor"); // create
    }

    hash->update(file);
    std::vector<uint8_t> dataHash = hash->digest();

    file.clear();
    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> data(fileSize, 0x00);
    file.read(reinterpret_cast<char*>(data.data()), data.size());

    std::vector<uint8_t> signature;

    sign(signature, data, key.getN(), key.getA(), hash);

    return D35Crypto::CAdES::create(1, contentType, username, pubKeyHash, hash->name(), "Fiat-Shamir", dataHash, signature);
}

void D35Crypto::FiatShamir::signCA(CAdES &userCAdES, const std::vector<uint8_t> &caPubKeyHash, const std::vector<uint8_t> &signedMessage, const FiatShamirKey &caPrivKey)
{
    // сделать независимость хэшей ЦА и клиента
    if (userCAdES.getHashAlgorithmId() != caPrivKey.getHashId())
    {
        throw std::runtime_error("wrong hashes error");
    }

    auto now = std::chrono::system_clock::now();
    uint64_t timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    std::vector<uint8_t> data(signedMessage.begin(), signedMessage.end());

    HashBase *hash = D35Crypto::hashIdToHashPtr(userCAdES.getHashAlgorithmId());
    hash->update(data);
    std::vector<uint8_t> dataHash = hash->digest();

    size_t dataSize = data.size();
    data.resize(dataSize + 8);
    data[dataSize    ] = static_cast<uint8_t>(timestamp >> 56);
    data[dataSize + 1] = static_cast<uint8_t>(timestamp >> 48);
    data[dataSize + 2] = static_cast<uint8_t>(timestamp >> 40);
    data[dataSize + 3] = static_cast<uint8_t>(timestamp >> 32);
    data[dataSize + 4] = static_cast<uint8_t>(timestamp >> 24);
    data[dataSize + 5] = static_cast<uint8_t>(timestamp >> 16);
    data[dataSize + 6] = static_cast<uint8_t>(timestamp >> 8 );
    data[dataSize + 7] = static_cast<uint8_t>(timestamp >> 0 );

    hash->update(signedMessage);
    std::vector<uint8_t> signedMessageDigest = hash->digest();

    std::vector<uint8_t> signature;
    sign(signature, data, caPrivKey.getN(), caPrivKey.getA(), hash);
    delete hash;

    userCAdES.appendCASign(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count(), caPubKeyHash, signedMessageDigest, signature);
}

bool D35Crypto::FiatShamir::checkSign(const std::vector<uint8_t> &userSignedMessage, const CAdES &cades, const FiatShamirKey &key)
{
    HashBase *hash = D35Crypto::hashIdToHashPtr(cades.getHashAlgorithmId());
    std::vector<uint8_t> cadesSign = cades.getSignature(); // extract st
    std::vector<uint8_t> s(cadesSign.begin(), cadesSign.begin() + hash->digestSize());
    std::vector<uint8_t> t(cadesSign.begin() + hash->digestSize(), cadesSign.end());

    NTL::ZZ tInt = NTL::ZZFromBytes(t.data(), t.size());
    NTL::ZZ w = tInt * tInt;
    std::vector<NTL::ZZ> b = key.getB();
    NTL::ZZ n = key.getN();
    int b_i = 0;

    for (int i = 0; i < hash->digestSize(); i++)
    {
        for (int offset = 0; offset < 8; offset++)
        {
            w = NTL::MulMod(w, NTL::PowerMod(b[b_i], (s[i] >> offset) & 1, n), n);
            b_i++;
        }
    }

    std::vector<uint8_t> dataBytes(userSignedMessage.begin(), userSignedMessage.begin() + cades.getUserSignHeaderPos());
    std::vector<uint8_t> wBytes(NTL::NumBytes(w));
    NTL::BytesFromZZ(wBytes.data(), w, wBytes.size());
    dataBytes.resize(dataBytes.size() + wBytes.size());
    std::copy(wBytes.begin(), wBytes.end(), dataBytes.begin() + (dataBytes.size() - wBytes.size()));
    hash->update(dataBytes);

    return hash->digest() == s;
}

bool D35Crypto::FiatShamir::checkCASign(const std::vector<uint8_t> &caSignedMessage, const CAdES &cades, const FiatShamirKey &caPubKey)
{
    HashBase *hash = D35Crypto::hashIdToHashPtr(cades.getHashAlgorithmId());
    uint64_t timestamp = cades.getCATimestamp();
    std::vector<uint8_t> cadesSign = cades.getCASignature();
    std::vector<uint8_t> s(cadesSign.begin(), cadesSign.begin() + hash->digestSize());
    std::vector<uint8_t> t(cadesSign.begin() + hash->digestSize(), cadesSign.end());

    NTL::ZZ tInt = NTL::ZZFromBytes(t.data(), t.size());
    NTL::ZZ w = tInt * tInt;
    std::vector<NTL::ZZ> b = caPubKey.getB();
    NTL::ZZ n = caPubKey.getN();
    int b_i = 0;

    for (int i = 0; i < hash->digestSize(); i++)
    {
        for (int offset = 0; offset < 8; offset++)
        {
            w = NTL::MulMod(w, NTL::PowerMod(b[b_i], (s[i] >> offset) & 1, n), n);
            b_i++;
        }
    }

    std::vector<uint8_t> data(caSignedMessage.begin(), caSignedMessage.begin() + cades.getCASignHeaderPos());
    hash->update(data);
    if (hash->digest() != cades.getCASignedMessageDigest())
    {
        return false;
    }

    size_t dataSize = data.size();
    data.resize(dataSize + 8);
    data[dataSize    ] = static_cast<uint8_t>(timestamp >> 56);
    data[dataSize + 1] = static_cast<uint8_t>(timestamp >> 48);
    data[dataSize + 2] = static_cast<uint8_t>(timestamp >> 40);
    data[dataSize + 3] = static_cast<uint8_t>(timestamp >> 32);
    data[dataSize + 4] = static_cast<uint8_t>(timestamp >> 24);
    data[dataSize + 5] = static_cast<uint8_t>(timestamp >> 16);
    data[dataSize + 6] = static_cast<uint8_t>(timestamp >> 8 );
    data[dataSize + 7] = static_cast<uint8_t>(timestamp >> 0 );

    std::vector<uint8_t> wBytes(NTL::NumBytes(w));
    NTL::BytesFromZZ(wBytes.data(), w, wBytes.size());
    data.resize(data.size() + wBytes.size());
    std::copy(wBytes.begin(), wBytes.end(), data.begin() + (data.size() - wBytes.size()));
    hash->update(data);

    return hash->digest() == s;
}

void D35Crypto::FiatShamir::sign(std::vector<uint8_t> &signature, const std::vector<uint8_t> &data, const NTL::ZZ &n, const std::vector<NTL::ZZ> &a, HashBase *hash)
{
    NTL::ZZ r = NTL::RandomBnd(n - 1) + 1; // random r
    NTL::ZZ u = NTL::PowerMod(r, 2, n);    // u = r^2 mod n

    std::vector<uint8_t> uBytes(NTL::NumBytes(u));
    NTL::BytesFromZZ(uBytes.data(), u, uBytes.size());

    std::vector<uint8_t> datarw(data.begin(), data.end());
    datarw.resize(datarw.size() + uBytes.size());
    std::copy(uBytes.begin(), uBytes.end(), datarw.begin() + data.size());
    hash->update(datarw);       // h(m, u)
    signature = hash->digest();

    NTL::ZZ t = r; // t = r MUL(i=1,m) a[i] ^ s[i] mod n
    int a_i = 0;
    for (int i = 0; i < signature.size(); i++)
    {
        for (int offset = 0; offset < 8; offset++)
        {
            t = NTL::MulMod(t, NTL::PowerMod(a[a_i], (signature[i] >> offset) & 1, n), n);
            a_i++;
        }
    }

    std::vector<uint8_t> tBytes(NTL::NumBytes(t));
    NTL::BytesFromZZ(tBytes.data(), t, tBytes.size());
    signature.resize(signature.size() + tBytes.size());
    std::copy(tBytes.begin(), tBytes.end(), signature.begin() + (signature.size() - tBytes.size()));
}
