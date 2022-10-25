#include <iostream>
#include <algorithm>

#include "../lib/hash/sha256.h"
#include "../lib/hash/sha512.h"


int main(int argc, char **argv)
{
    //sha256
    D35Crypto::SHA256 sha256;
    sha256.update("AMOGUS");
    std::cout << "SHA256(\"AMOGUS\") = " << sha256.hexDigest() << std::endl;

    sha256.update("Продолжение приключений междуяхтовых сражений\n"
                  "Началось в день после бури, когда встретил свой фрегат\n"
                  "Пусть узнают гости моря всё владычество пирата!\n"
                  "Кто владеет всем морем — настоящий тот пират!\n"
                  "Грохот пушек, свист картечи, начат бой внезапной встречей\n"
                  "Звон металла, пули, сабли — так идёт смертельный бой\n"
                  "Повстречались два фрегата в синеве морского ада\n"
                  "Наш пиратский корабль обернулся вам бедой!\n"
                  "Наш пиратский корабль обернулся вам бедой!");
    std::cout << "SHA256(UTF8 TEXT) = " << sha256.hexDigest() << std::endl;

    std::ifstream infile("/tmp/binary", std::ios::binary);
    sha256.update(infile);
    infile.close();
    std::cout << "SHA256(FILE) = " << sha256.hexDigest() << std::endl;


    //sha512
    D35Crypto::SHA512 sha512;
    sha512.update("AMOGUS");
    std::cout << "SHA256(\"AMOGUS\") = " << sha512.hexDigest() << std::endl;

    sha512.update("Продолжение приключений междуяхтовых сражений\n"
                    "Началось в день после бури, когда встретил свой фрегат\n"
                    "Пусть узнают гости моря всё владычество пирата!\n"
                    "Кто владеет всем морем — настоящий тот пират!\n"
                    "Грохот пушек, свист картечи, начат бой внезапной встречей\n"
                    "Звон металла, пули, сабли — так идёт смертельный бой\n"
                    "Повстречались два фрегата в синеве морского ада\n"
                    "Наш пиратский корабль обернулся вам бедой!\n"
                    "Наш пиратский корабль обернулся вам бедой!");
    std::cout << "SHA512(UTF8 TEXT) = " << sha512.hexDigest() << std::endl;

    infile.open("/tmp/binary", std::ios::binary);
    sha512.update(infile);
    infile.close();
    std::cout << "SHA512(FILE) = " << sha512.hexDigest() << std::endl;
}
