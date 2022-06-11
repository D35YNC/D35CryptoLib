#include "fiatshamir.h"
#include "../utils.h"


MyCryptoLib::CAdES MyCryptoLib::FiatShamir::sign(const std::string &username, const std::vector<uint8_t> &pubKeyHash, const std::string &data,  MyCryptoLib::HashBase *hash, const FiatShamirKey &key)
{
    return MyCryptoLib::FiatShamir::sign(username, pubKeyHash, "TEXT", std::vector<uint8_t>(data.begin(), data.end()), hash, key);
}

MyCryptoLib::CAdES MyCryptoLib::FiatShamir::sign(const std::string &username, const std::vector<uint8_t> &pubKeyHash, const std::string &contentType, const std::vector<uint8_t> &data, MyCryptoLib::HashBase *hash, const FiatShamirKey &key)
{
    if (hash->name() != key.getHashId())
    {
        throw std::runtime_error("wrong hashes error");
    }

    hash->update(data);
    std::vector<uint8_t> dataHash = hash->digest();
    std::vector<uint8_t> signature;

    sign(signature, data, key.getN(), key.getA(), hash);

    return MyCryptoLib::CAdES::create(1, contentType, username, pubKeyHash, hash->name(), "Fiat-Shamir", dataHash, signature);
}

MyCryptoLib::CAdES MyCryptoLib::FiatShamir::sign(const std::string &username, const std::vector<uint8_t> &pubKeyHash, const std::string &contentType, const std::string &filename, MyCryptoLib::HashBase *hash, const FiatShamirKey &key)
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

    return MyCryptoLib::CAdES::create(1, contentType, username, pubKeyHash, hash->name(), "Fiat-Shamir", dataHash, signature);
}

void MyCryptoLib::FiatShamir::signCA(CAdES &userCAdES, const std::vector<uint8_t> &caPubKeyHash, const std::vector<uint8_t> &data, const FiatShamirKey &caPrivKey)
{
    // сделать независимость хэшей ЦА и клиента
    if (userCAdES.getHashAlgorithmId() != caPrivKey.getHashId())
    {
        throw std::runtime_error("wrong hashes error");
    }
    HashBase *hash = MyCryptoLib::hashIdToHashPtr(userCAdES.getHashAlgorithmId());
    hash->update(data);
    std::vector<uint8_t> dataHash = hash->digest();
    std::vector<uint8_t> signature;

    sign(signature, data, caPrivKey.getN(), caPrivKey.getA(), hash);

    userCAdES.appendCASign(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count(), caPubKeyHash, signature);
}

bool MyCryptoLib::FiatShamir::checkSign(const std::vector<uint8_t> &data, const CAdES &cades, const FiatShamirKey &key)
{
    HashBase *hash = MyCryptoLib::hashIdToHashPtr(cades.getHashAlgorithmId());
    std::vector<uint8_t> cadesSign = cades.getSignature();
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

    std::vector<uint8_t> dataBytes(data.begin(), data.end());
    std::vector<uint8_t> wBytes(NTL::NumBytes(w));
    NTL::BytesFromZZ(wBytes.data(), w, wBytes.size());
    dataBytes.resize(dataBytes.size() + wBytes.size());
    std::copy(wBytes.begin(), wBytes.end(), dataBytes.begin() + (dataBytes.size() - wBytes.size()));
    hash->update(dataBytes);

    return hash->digest() == s;
}

bool MyCryptoLib::FiatShamir::checkCASign(const std::vector<uint8_t> &data, const CAdES &cades, const FiatShamirKey &caPubKey)
{
    HashBase *hash = MyCryptoLib::hashIdToHashPtr(cades.getHashAlgorithmId());
    std::vector<uint8_t> cadesSign = cades.getCASignature();
    std::vector<uint8_t> s(cadesSign.begin(), cadesSign.begin() + hash->digestSize());
    std::vector<uint8_t> t(cadesSign.begin() + hash->digestSize(), cadesSign.end());


    NTL::ZZ tInt = NTL::ZZFromBytes(t.data(), t.size());
    NTL::ZZ w(tInt * tInt);
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

    std::vector<uint8_t> dataBytes(data.begin(), data.end());
    std::vector<uint8_t> wBytes(NTL::NumBytes(w));
    NTL::BytesFromZZ(wBytes.data(), w, wBytes.size());
    dataBytes.resize(dataBytes.size() + wBytes.size());
    std::copy(wBytes.begin(), wBytes.end(), dataBytes.begin() + (dataBytes.size() - wBytes.size()));
    hash->update(dataBytes);

    return hash->digest() == s;
}

void MyCryptoLib::FiatShamir::sign(std::vector<uint8_t> &signature, const std::vector<uint8_t> &data, const NTL::ZZ &n, const std::vector<NTL::ZZ> &a, HashBase *hash)
{
    NTL::ZZ r = NTL::RandomBnd(n - 1) + 1;
    NTL::ZZ u = NTL::PowerMod(r, 2, n);

    std::vector<uint8_t> dataBytes(data.begin(), data.end());

    std::vector<uint8_t> uBytes(NTL::NumBytes(u));
    NTL::BytesFromZZ(uBytes.data(), u, uBytes.size());

    dataBytes.resize(dataBytes.size() + uBytes.size());
    std::copy(uBytes.begin(), uBytes.end(), dataBytes.begin() + (dataBytes.size() - uBytes.size()));
    hash->update(dataBytes);
    signature = hash->digest();

    NTL::ZZ t = r;
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
