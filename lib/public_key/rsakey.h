#ifndef RSAKEY_H
#define RSAKEY_H

#include <vector>
#include <string>
#include <sstream>
#include <random>
#include <fstream>
#include <algorithm>

#include <NTL/ZZ.h>
//#include <gmpxx.h>

#include "../exceptions.h"


namespace D35Crypto
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
    RSAKey(NTL::ZZ _p, NTL::ZZ _q, NTL::ZZ _e, NTL::ZZ _d) :
        n(_p * _q), e(_e),
        d(_d), p(_p), q(_q)
    { }

    static RSAKey generate(size_t bitSize);

    /*TODO: ASN1 Encoding*/
    static RSAKey pubKeyFromBytes(const std::vector<uint8_t> &buffer, bool skipHeaders = false);
    static RSAKey privKeyFromBytes(const std::vector<uint8_t> &buffer, bool skipHeaders = false);
    static RSAKey pubKeyFromFile(const std::string &filename);
    static RSAKey privKeyFromFile(const std::string &filename);

    bool isPrivate() const;
    bool canSign() const;
    bool canEncrypt() const;
    bool canDecrypt() const;
    size_t blockSize() const;
    size_t size() const;

    std::vector<uint8_t> exportPrivateKeyBytes() const;
    std::vector<uint8_t> exportPublicKeyBytes() const;

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
