#include <iostream>
#include <vector>
#include <string>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <algorithm>

#include <NTL/ZZ.h>

std::vector<NTL::ZZ> gen_poly(const NTL::ZZ &p, int pwr)
{
    std::vector<NTL::ZZ> poly(pwr + 1);
    for (int i = 0; i < pwr + 1; i++)
    {
        poly[i] = NTL::RandomBnd(p);
    }
    return poly;
}

NTL::ZZ f_x(const NTL::ZZ &x, const std::vector<NTL::ZZ> &poly)
{
    NTL::ZZ result = poly[0];
    for (int i = 1; i < poly.size(); i++)
    {
        NTL::MulAddTo(result, poly[i], NTL::power(x, i));
    }
    return result;
}

int main(int argc, char **argv)
{
    NTL::ZZ p = NTL::GenPrime_ZZ(512);
    int n = 7;
    int t = 4;

    std::vector<NTL::ZZ> poly = gen_poly(p, t);
    NTL::ZZ secret = poly[0];

    std::vector<NTL::ZZ> r(n);
    for (int i = 0; i < r.size(); i++)
    {
        r[i] = NTL::RandomBnd(p);
    }

    NTL::ZZ tmp;
    std::vector<NTL::ZZ> s(n);
    for (int i = 0; i < s.size(); i++)
    {
        tmp = 1;
        for (int j = 0; j < s.size(); j++)
        {
            if (i != j)
            {
                NTL::ZZ z, t1, t2;
                NTL::XGCD(t1, t2, z, p, NTL::SubMod(r[j], r[i], p));
                tmp *= r[j] * z;
            }
        }
        s[i] = tmp;
    }


    // ===
    // r - x
    // s - y

    NTL::ZZ recovered_s(0);
    for (int i = 0; i < n; i++)
    {
        NTL::MulAddTo(recovered_s, f_x(r[i], poly), s[i]);
    }

    std::cout << (recovered_s % p) << std::endl << secret << std::endl;
    // if eq -> then all righth
    return 0;
}
