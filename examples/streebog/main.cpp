#include <iostream>

#include "../lib/hash/streebog.h"


int main(int argc, char **argv)
{
    D35Crypto::Streebog streebog;
    streebog.update("AMOGUS");
    std::cout << "STREEBOG512(\"AMOGUS\") = " << streebog.hexDigest() << std::endl;

    streebog.update("Продолжение приключений междуяхтовых сражений\n"
                    "Началось в день после бури, когда встретил свой фрегат\n"
                    "Пусть узнают гости моря всё владычество пирата!\n"
                    "Кто владеет всем морем — настоящий тот пират!\n"
                    "Грохот пушек, свист картечи, начат бой внезапной встречей\n"
                    "Звон металла, пули, сабли — так идёт смертельный бой\n"
                    "Повстречались два фрегата в синеве морского ада\n"
                    "Наш пиратский корабль обернулся вам бедой!\n"
                    "Наш пиратский корабль обернулся вам бедой!");
    std::cout << "STREEBOG512(UTF8 TEXT) = " << streebog.hexDigest() << std::endl;

    std::ifstream infile("/tmp/binary", std::ios::binary);
    streebog.update(infile);
    infile.close();
    std::cout << "STREEBOG256(FILE) = " << streebog.hexDigest() << std::endl;


    streebog.setMode(256);

    streebog.update("AMOGUS");
    std::cout << "STREEBOG256(\"AMOGUS\") = " << streebog.hexDigest() << std::endl;

    streebog.update("Продолжение приключений междуяхтовых сражений\n"
                    "Началось в день после бури, когда встретил свой фрегат\n"
                    "Пусть узнают гости моря всё владычество пирата!\n"
                    "Кто владеет всем морем — настоящий тот пират!\n"
                    "Грохот пушек, свист картечи, начат бой внезапной встречей\n"
                    "Звон металла, пули, сабли — так идёт смертельный бой\n"
                    "Повстречались два фрегата в синеве морского ада\n"
                    "Наш пиратский корабль обернулся вам бедой!\n"
                    "Наш пиратский корабль обернулся вам бедой!");
    std::cout << "STREEBOG256(UTF8 TEXT) = " << streebog.hexDigest() << std::endl;

    infile.open("/tmp/binary", std::ios::binary);
    streebog.update(infile);
    infile.close();
    std::cout << "STREEBOG256(FILE) = " << streebog.hexDigest() << std::endl;
}
