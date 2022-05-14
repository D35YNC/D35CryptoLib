#ifndef RSAKEY_H
#define RSAKEY_H

#include <vector>
#include <string>
#include <sstream>
#include <random>
#include <fstream>
#include <algorithm>

#include <NTL/ZZ.h>
#include <gmpxx.h>

#include "../exceptions.h"

#include "../encoding/base64.h"
#include "../encoding/pkcs8.h"
#include "../encoding/pkcs12.h"


namespace MyCryptoLib
{

class RSAKey
{
public:
    // For generation & custom params
    RSAKey(NTL::ZZ _n, NTL::ZZ _e, NTL::ZZ _p, NTL::ZZ _q, NTL::ZZ _d) :
        n(_n), e(_e),
        p(_p), q(_q), d(_d)
    { }
    // For custom pub key
    RSAKey(NTL::ZZ _n, NTL::ZZ _e) :
        n(_n), e(_e),
        d(NTL::conv<NTL::ZZ>(0)), p(NTL::conv<NTL::ZZ>(0)), q(NTL::conv<NTL::ZZ>(0))
    { }
    // For custom priv key + extract pubkey
    RSAKey(NTL::ZZ _p, NTL::ZZ _q, NTL::ZZ _e) :
        n(_p * _q), e(_e),
        d(NTL::conv<NTL::ZZ>(0)), p(_p), q(_q)
    {
        NTL::ZZ phi = (p - 1) * (q - 1);
        d = NTL::InvMod(e % phi, phi);
    }

    RSAKey(const PKCS12 &pkcs12Obj);
    RSAKey(const PKCS8 &pkcs8Obj);

    static RSAKey generate(size_t bitSize);
    static RSAKey fromPKCS8(const PKCS8 &pkcs8obj);
    static RSAKey fromPKCS12(const PKCS12 &pkcs12obj);
    static RSAKey fromPKCS8File(std::string filename);
    static RSAKey fromPKCS12File(std::string filename);

    bool isPrivate() const;
    bool canEncrypt() const;
    bool canDecrypt() const;
    size_t size() const;

    PKCS12 exportPrivateKey();
    PKCS8 exportPublicKey();

    std::vector<uint8_t> exportPrivateKeyBytes();
    std::vector<uint8_t> exportPublicKeyBytes();

    NTL::ZZ getModulus() const;
    NTL::ZZ getPublicExponent() const;
    NTL::ZZ getPrivateExponent() const;

private:
    NTL::ZZ p;
    NTL::ZZ q;
    NTL::ZZ d;
    NTL::ZZ n;
    NTL::ZZ e;
};

}

#endif // RSAKEY_H
