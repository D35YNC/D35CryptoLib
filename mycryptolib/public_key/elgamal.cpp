#include "elgamal.h"

#include "../utils.h"

MyCryptoLib::CAdES MyCryptoLib::ElGamal::sign(
        const std::string &username,
        const std::vector<uint8_t> &pubKeyHash,
        const std::string &data,
        MyCryptoLib::HashBase *hash,
        const ElGamalKey &key)
{
    return MyCryptoLib::ElGamal::sign(username, pubKeyHash, "TEXT", std::vector<uint8_t>(data.begin(), data.end()), hash, key);
}

MyCryptoLib::CAdES MyCryptoLib::ElGamal::sign(
        const std::string &username,
        const std::vector<uint8_t> &pubKeyHash,
        const std::string &contentType,
        const std::vector<uint8_t> &data,
        MyCryptoLib::HashBase *hash,
        const ElGamalKey &key)
{
    hash->update(data);
    std::vector<uint8_t> originalHash = hash->digest();
    std::vector<uint8_t> signature = hash->digest();

    NTL::ZZ r;
    NTL::ZZ gamma;
    NTL::ZZ delta;
    NTL::ZZ signatureInt = NTL::ZZFromBytes(signature.data(), signature.size());

    NTL::ZZ gcdResult;
    NTL::ZZ gcdA;
    NTL::ZZ gcdB;
    while (true)
    {
        r = NTL::RandomBnd(key.getP() - 2);
        NTL::XGCD(gcdResult, gcdA, gcdB, r, key.getP() - 1);
        if (gcdResult == NTL::conv<NTL::ZZ>(1))
        {
            break;
        }
    }

    gamma = NTL::PowerMod(key.getAlpha(), r, key.getP());
    delta = ((signatureInt - (key.getA() * gamma)) * gcdA) % (key.getP() - 1);

    signature.resize(NTL::NumBytes(gamma) + NTL::NumBytes(delta));
    NTL::BytesFromZZ(&signature.data()[0], gamma, NTL::NumBytes(gamma));
    NTL::BytesFromZZ(&signature.data()[NTL::NumBytes(gamma)], delta, NTL::NumBytes(delta));

    return CAdES::create(1, contentType, username, pubKeyHash, hash->name(), "DSAdsi", originalHash, signature);
}

MyCryptoLib::CAdES MyCryptoLib::ElGamal::sign(
        const std::string &username,
        const std::vector<uint8_t> &pubKeyHash,
        const std::string &contentType,
        const std::string &filename,
        MyCryptoLib::HashBase *hash,
        const ElGamalKey &privKey)
{
    std::ifstream signingFile(filename);
    hash->update(signingFile);

    std::vector<uint8_t> originalHash = hash->digest();
    std::vector<uint8_t> signature = hash->digest();

    sign(signature, privKey.getA(), privKey.getAlpha(), privKey.getP());

    return CAdES::create(1, contentType, username, pubKeyHash, hash->name(), "DSAdsi", originalHash, signature);
}

void MyCryptoLib::ElGamal::signCA(CAdES &userCAdES, const std::vector<uint8_t> &caPubKeyHash, const std::vector<uint8_t> &signedMessage, const ElGamalKey &caPrivKey)
{
    auto now = std::chrono::system_clock::now();
    uint64_t timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    std::vector<uint8_t> data(signedMessage.begin(), signedMessage.end());
    data.resize(data.size() + 8);
    data[signedMessage.size()] = timestamp >> 56;
    data[signedMessage.size() + 1] = timestamp >> 48;
    data[signedMessage.size() + 2] = timestamp >> 40;
    data[signedMessage.size() + 3] = timestamp >> 32;
    data[signedMessage.size() + 4] = timestamp >> 24;
    data[signedMessage.size() + 5] = timestamp >> 16;
    data[signedMessage.size() + 6] = timestamp >> 8;
    data[signedMessage.size() + 7] = timestamp;

    HashBase *hash = MyCryptoLib::hashIdToHashPtr(userCAdES.getHashAlgorithmId());
    hash->update(data);
    std::vector<uint8_t> signature = hash->digest();
    hash->update(signedMessage);
    std::vector<uint8_t> signedMessageDigest = hash->digest();
    delete hash;
    sign(signature, caPrivKey.getA(), caPrivKey.getAlpha(), caPrivKey.getP());

    userCAdES.appendCASign(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count(), caPubKeyHash, signedMessageDigest, signature);
}

bool MyCryptoLib::ElGamal::checkSign(const std::vector<uint8_t> &userSignedMessage, const CAdES &cades, const ElGamalKey &key)
{
    std::vector<uint8_t> digest = cades.getContentHash();
    NTL::ZZ digestInt = NTL::ZZFromBytes(digest.data(), digest.size());

    std::vector<uint8_t> signature = cades.getSignature();
    NTL::ZZ gamma = NTL::ZZFromBytes(&signature.data()[0], static_cast<long>(signature.size() / 2));
    NTL::ZZ delta = NTL::ZZFromBytes(&signature.data()[static_cast<long>(signature.size() / 2)], static_cast<long>(signature.size() / 2));

    NTL::ZZ stage0 = NTL::PowerMod(key.getBeta(), gamma, key.getP());
    NTL::ZZ stage1 = NTL::PowerMod(gamma, delta, key.getP());
    NTL::ZZ stage2 = NTL::MulMod(stage0, stage1, key.getP());
    NTL::ZZ stage3 = NTL::PowerMod(key.getAlpha(), digestInt, key.getP());

    HashBase *hash = MyCryptoLib::hashIdToHashPtr(cades.getHashAlgorithmId());
    hash->update(std::vector<uint8_t>(userSignedMessage.begin(), userSignedMessage.begin() + cades.getUserSignHeaderPos()));
    std::vector<uint8_t> actualDigest = hash->digest();
    delete hash;

    NTL::ZZ actualDigestInt = NTL::ZZFromBytes(actualDigest.data(), actualDigest.size());
    actualDigestInt = NTL::PowerMod(key.getAlpha(), actualDigestInt, key.getP());

    return stage2 == stage3 && stage2 == actualDigestInt;
}

bool MyCryptoLib::ElGamal::checkCASign(const std::vector<uint8_t> &signedMessage, const CAdES &cades, const ElGamalKey &caPubKey)
{
    std::vector<uint8_t> signedMessageDigest = cades.getCASignedMessageDigest();
    std::vector<uint8_t> signature = cades.getCASignature();
    NTL::ZZ digestInt = NTL::ZZFromBytes(signedMessageDigest.data(), signedMessageDigest.size());

    NTL::ZZ gamma = NTL::ZZFromBytes(&signature.data()[0], static_cast<long>(signature.size() / 2));
    NTL::ZZ delta = NTL::ZZFromBytes(&signature.data()[static_cast<long>(signature.size() / 2)], static_cast<long>(signature.size() / 2));

    NTL::ZZ stage0 = NTL::PowerMod(caPubKey.getBeta(), gamma, caPubKey.getP());
    NTL::ZZ stage1 = NTL::PowerMod(gamma, delta, caPubKey.getP());
    NTL::ZZ stage2 = NTL::MulMod(stage0, stage1, caPubKey.getP());
    NTL::ZZ stage3 = NTL::PowerMod(caPubKey.getAlpha(), digestInt, caPubKey.getP());

    uint64_t timestamp = cades.getCATimestamp();
    std::vector<uint8_t> data(signedMessage.begin(), signedMessage.begin() + cades.getCASignHeaderPos());
    size_t dataSize = data.size();
    data.resize(dataSize + 8);
    data[dataSize] = timestamp >> 56;
    data[dataSize + 1] = timestamp >> 48;
    data[dataSize + 2] = timestamp >> 40;
    data[dataSize + 3] = timestamp >> 32;
    data[dataSize + 4] = timestamp >> 24;
    data[dataSize + 5] = timestamp >> 16;
    data[dataSize + 6] = timestamp >> 8;
    data[dataSize + 7] = timestamp;

    HashBase *hash = MyCryptoLib::hashIdToHashPtr(cades.getHashAlgorithmId());
    hash->update(data);
    std::vector<uint8_t> actualDigest = hash->digest();
    delete hash;

    NTL::ZZ signedDigestInt = NTL::ZZFromBytes(signedMessageDigest.data(), signedMessageDigest.size());
    NTL::ZZ actualDigestInt = NTL::ZZFromBytes(actualDigest.data(), actualDigest.size());
    actualDigestInt = NTL::PowerMod(caPubKey.getAlpha(), actualDigestInt, caPubKey.getP());
    /// correct
//    return stage2 == stage3 && stage2 == actualDigestInt;
    return stage2 == signedDigestInt && stage2 == actualDigestInt;
}

void MyCryptoLib::ElGamal::sign(std::vector<uint8_t> &signature, NTL::ZZ a, NTL::ZZ alpha, NTL::ZZ p)
{
    NTL::ZZ signatureInt = NTL::ZZFromBytes(signature.data(), signature.size());

    NTL::ZZ r;
    NTL::ZZ gcdResult;
    NTL::ZZ gcdA;
    NTL::ZZ gcdB;

    size_t ksize = NTL::NumBytes(p); // key.size();

    while (gcdResult != NTL::conv<NTL::ZZ>(1))
    {
        r = NTL::RandomBnd(p - 2);
        NTL::XGCD(gcdResult, gcdA, gcdB, r, p - 1);
    }

    NTL::ZZ gamma = NTL::PowerMod(alpha, r, p);
    NTL::ZZ delta = ((signatureInt - (a * gamma)) * gcdA) % (p - 1);

    signature.resize(ksize * 2);
    NTL::BytesFromZZ(&signature.data()[ksize - NTL::NumBytes(gamma)], gamma, NTL::NumBytes(gamma));
    NTL::BytesFromZZ(&signature.data()[(ksize * 2) - NTL::NumBytes(delta)], delta, NTL::NumBytes(delta));
}
