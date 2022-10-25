#ifndef ELGAMALKEY_H
#define ELGAMALKEY_H

#include <vector>
#include <string>
#include <random>

#include <NTL/ZZ.h>

#include "../exceptions.h"

#include "../encoding/base64.h"
#include "../encoding/pkcs8.h"
#include "../encoding/pkcs12.h"

namespace D35Crypto
{

class ElGamalKey
{
public:
    // Custom
    ElGamalKey(NTL::ZZ a, NTL::ZZ p, NTL::ZZ alpha, NTL::ZZ beta) :
        a(a), p(p), alpha(alpha), beta(beta)
    { }
    // Privkey
    ElGamalKey(NTL::ZZ a) :
        a(a), p(NTL::conv<NTL::ZZ>(0)), alpha(NTL::conv<NTL::ZZ>(0)), beta(NTL::conv<NTL::ZZ>(0))
    { }
    // Pubkey
    ElGamalKey(NTL::ZZ p, NTL::ZZ alpha, NTL::ZZ beta) :
        a(NTL::conv<NTL::ZZ>(0)), p(p), alpha(alpha), beta(beta)
    { }

    static ElGamalKey generate(size_t bitSize);
    static ElGamalKey fromPKCS8(PKCS8 *pkcs8obj);
    static ElGamalKey fromPKCS12(PKCS12 *pkcs12obj);
    static ElGamalKey fromPKCS8File(const std::string &filename);
    static ElGamalKey fromPKCS12File(const std::string &filename);

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

    // pubk
    NTL::ZZ getAlpha() const;
    NTL::ZZ getBeta() const;
    NTL::ZZ getP() const;
    //privk
    NTL::ZZ getA() const;
private:
    NTL::ZZ a;
    NTL::ZZ p;
    NTL::ZZ alpha;
    NTL::ZZ beta;
};

}

#endif // ELGAMALKEY_H
