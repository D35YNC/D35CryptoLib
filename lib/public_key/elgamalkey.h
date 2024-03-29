#ifndef ELGAMALKEY_H
#define ELGAMALKEY_H

#include <vector>
#include <string>
#include <random>

#include <NTL/ZZ.h>

#include "../exceptions.h"
#include "../encoding/base64.h"

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

//    static ElGamalKey publicKeyFromBytes(const std::vector<uint8_t> &buffer, bool skipHeaders = false);
//    static ElGamalKey privateKeyFromBytes(const std::vector<uint8_t> &buffer, bool skipHeaders = false);

    bool isPrivate() const noexcept;
    bool canSign() const noexcept;
    bool canEncrypt() const noexcept;
    bool canDecrypt() const noexcept;
    size_t blockSize() const;
    size_t size() const;

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
