#ifndef ELGAMALKEY_H
#define ELGAMALKEY_H

#include <vector>
#include <string>
#include <random>

#include <NTL/ZZ.h>

namespace MyCryptoLib
{

class ElGamalKey
{
public:
    ElGamalKey(NTL::ZZ a) :
        a(a), p(NTL::conv<NTL::ZZ>(0)), alpha(NTL::conv<NTL::ZZ>(0)), beta(NTL::conv<NTL::ZZ>(0))
    { }
    ElGamalKey(NTL::ZZ p, NTL::ZZ alpha, NTL::ZZ beta) :
        a(NTL::conv<NTL::ZZ>(0)), p(p), alpha(alpha), beta(beta)
    { }
    ElGamalKey(NTL::ZZ a, NTL::ZZ p, NTL::ZZ alpha, NTL::ZZ beta) :
        a(a), p(p), alpha(alpha), beta(beta)
    { }

    static ElGamalKey generate(size_t bitSize)
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
        NTL::ZZ phi;

        while (NTL::ProbPrime(p, 100) == 0)
        {
            alpha = NTL::GenGermainPrime_ZZ(static_cast<long>(bitSize));
            p = (2 * alpha) + 1;
            phi = p - 1;
        }

        // phi = p - 1
        // randomBnd = 0 <= ret <= n - 1
        // чисто ради перестраховки от 0
        phi = NTL::RandomBnd(phi - 2) + 1;
        // a == phi
        beta = NTL::PowerMod(alpha, phi, p);

        if (NTL::conv<int>(NTL::PowerMod(phi, p - 1, p)) != 1)
        {
            throw std::exception(); // Что то пошло не так. ХЗ как выбирать альфу. по идее так
        }

        return ElGamalKey(phi, p, alpha, beta);
    }

    bool isPrivate() const
    {
        return a != 0;
    }
    size_t size() const
    {
        return NTL::NumBytes(a);
    }

private:
    NTL::ZZ a;
    NTL::ZZ p;
    NTL::ZZ alpha;
    NTL::ZZ beta;
};

}

#endif // ELGAMALKEY_H
