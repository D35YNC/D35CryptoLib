#ifndef FIATSHAMIRKEY_H
#define FIATSHAMIRKEY_H

#include <vector>
#include <string>
#include <sstream>
#include <random>
#include <fstream>
#include <algorithm>

#include <NTL/ZZ.h>
#include <gmpxx.h>

#include "../exceptions.h"

#include "../hash/hash_base.h"
#include "../hash/sha256.h"
#include "../hash/sha512.h"
#include "../hash/streebog.h"
#include "../encoding/base64.h"
#include "../encoding/pkcs8.h"
#include "../encoding/pkcs12.h"


namespace D35Crypto
{
class FiatShamirKey
{
public:
    // For generation & custom params
    FiatShamirKey(NTL::ZZ _p, NTL::ZZ _q, NTL::ZZ _n, std::vector<NTL::ZZ> _a, std::vector<NTL::ZZ> _b, HashBase *_hash) : //NTL::ZZ
        p(_p), q(_q), n(_n), a(_a), b(_b), hashId(_hash->name())
    { }
    // For custom pub key
    FiatShamirKey(NTL::ZZ _n, std::vector<NTL::ZZ> _b, HashBase *_hash) :
        n(_n), p(NTL::conv<NTL::ZZ>(0)), q(NTL::conv<NTL::ZZ>(0)),
        a({}), b(_b), hashId(_hash->name())
    { }
    // For custom priv key & extract pubkey
    FiatShamirKey(NTL::ZZ _p, NTL::ZZ _q, std::vector<NTL::ZZ> _a, HashBase *_hash) :
        n(_p * _q), p(_p), q(_q), a(_a), b({}), hashId(_hash->name())
    {
        this->b.resize(_a.size());
        for (int i = 0; i < this->b.size(); i++)
        {
            b[i] = NTL::PowerMod(NTL::InvMod(a[i], n), 2, n);
        }
    }

    static FiatShamirKey generate(size_t bitSize, HashBase *_hash);
    static FiatShamirKey fromPKCS8(PKCS8 *pkcs8obj);
    static FiatShamirKey fromPKCS12(PKCS12 *pkcs12obj);
    static FiatShamirKey fromPKCS8File(const std::string &filename);
    static FiatShamirKey fromPKCS12File(const std::string &filename);

    bool isPrivate() const;
    bool canSign() const;
    bool canEncrypt() const;
    bool canDecrypt() const;
    size_t blockSize() const;
    size_t size() const;

    PKCS12 exportPrivateKey() const;
    PKCS8 exportPublicKey() const;

    std::vector<uint8_t> exportPrivateKeyBytes() const;
    std::vector<uint8_t> exportPublicKeyBytes() const;

    NTL::ZZ getP() const;
    NTL::ZZ getQ() const;
    NTL::ZZ getN() const;
    std::vector<NTL::ZZ> getA() const;
    std::vector<NTL::ZZ> getB() const;
    std::string getHashId() const;

private:
    NTL::ZZ p; // prime
    NTL::ZZ q; // prime
    NTL::ZZ n; // = p * q
    std::vector<NTL::ZZ> a; // random
    std::vector<NTL::ZZ> b; // (ai^-1(mod n) )^2 (mod n)
    std::string hashId;
};

}
#endif // FIATSHAMIRKEY_H
