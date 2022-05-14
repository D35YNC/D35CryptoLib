#include <iostream>
#include <algorithm>

#include "../mycryptolib/hash/sha256.h"
#include "../mycryptolib/hash/sha512.h"

void usage()
{
    std::cout << "Usage: lab5 {--digest (256 or 512)} { --cin | --file FILENAME | --string VALUE }" << std::endl;
    exit(0);
}

int main(int argc, char **argv)
{
    // Arguments parsing
    const std::vector<std::string> avArgs = {"--digest", "--cin", "--string", "--file"};
    std::vector<std::string> args;
    if (argc > 1)
    {
        args.assign(argv + 1, argv + argc);
    }
    else
    {
        usage();
    }

    int digestSize = -1; // disgest size
    int inputMode = -1;  // interactive/string/file
    bool nextIsParam = false;  // При трю - следующий args[i + 1] фактически не парсится тк уже был распраршен когда было установлено трю
    std::string inputData;     // Filename if inputMode = 2; String to encode if inpmode = 1; std::getline if mode --cin = 0 after parsing

    for (int i = 0; i < args.size(); i++)
    {
        if (nextIsParam)
        {
            nextIsParam = false;
            continue;
        }
        auto iter_ = std::find(avArgs.begin(), avArgs.end(), args[i]); // Да кто такой ваш итератор
        if (args[i].rfind("--", 0) == 0 && iter_ != avArgs.end())
        {
            // Это аргумент cmd
            // и он разренеше

            int index = iter_ - avArgs.begin();

            if (index == 0)
            {
                try
                {
                    if (i + 1 < args.size())
                    {
                        digestSize = std::stoi(args[i + 1]);
                        nextIsParam = true;
                    }
                    else
                    {
                        usage(); // Тут выход при невозможности забрать параметр для аргумента
                    }
                }
                catch (std::invalid_argument)
                {
                    std::cerr << "Digest size must be int" << std::endl;
                    usage();
                }
            }
            else if (0 < index && index < avArgs.size())
            {
                inputMode = index - 1;
                // 0 == --cin
                // 1 == --string
                // 2 == --file

                if (inputMode > 0)
                {
                    if (i + 1 < args.size())
                    {
                        inputData = args[i + 1];
                        nextIsParam = true;
                    }
                    else
                    {
                        usage(); // Тут выход при невозможности забрать параметр для аргумента
                    }
                }
            }
        }
    }

    if ((digestSize != 256 && digestSize != 512) || inputMode == -1)
    {
        usage();
    }

    if (digestSize == 256)
    {
        MyCryptoLib::SHA256 sha;
        if (inputMode == 2)
        {
            std::ifstream inFile(inputData);
            sha.update(inFile);
        }
        else
        {
            sha.update(inputData);
        }
        std::cout << sha.hexDigest();
    }
    else
    {
        MyCryptoLib::SHA512 sha;

        if (inputMode == 2)
        {
            std::ifstream inFile(inputData);
            sha.update(inFile);
        }
        else
        {
            sha.update(inputData);
        }
        std::cout << sha.hexDigest();
    }


//    std::ifstream infile("/home/d35ync/COPT/logo.xcf", std::ios::binary);
//    //sha256
//    MyCryptoLib::SHA256 sha256;

//    sha256.update("Киберкарась");
//    std::cout << "SHA256(\"Киберкарась\") = " << sha256.hexDigest() << std::endl;

//    sha256.update("AMOGUS");
//    std::cout << "SHA256(\"AMOGUS\") = " << sha256.hexDigest() << std::endl;

//    sha256.update("Продолжение приключений междуяхтовых сражений\n"
//                  "Началось в день после бури, когда встретил свой фрегат\n"
//                  "Пусть узнают гости моря всё владычество пирата!\n"
//                  "Кто владеет всем морем — настоящий тот пират!\n"
//                  "Грохот пушек, свист картечи, начат бой внезапной встречей\n"
//                  "Звон металла, пули, сабли — так идёт смертельный бой\n"
//                  "Повстречались два фрегата в синеве морского ада\n"
//                  "Наш пиратский корабль обернулся вам бедой!\n"
//                  "Наш пиратский корабль обернулся вам бедой!");
//    std::cout << "SHA256(UTF8 TEXT) = " << sha256.hexDigest() << std::endl;

//    infile.open("/home/d35ync/COPT/logo.xcf", std::ios::binary);
//    sha256.update(infile);
//    infile.close();
//    std::cout << "SHA256(FILE) = " << sha256.hexDigest() << std::endl;


//    //sha512
//    MyCryptoLib::SHA512 sha512;
//    sha512.update("Киберкарась");
//    std::cout << "SHA512(\"Киберкарась\") = " << sha512.hexDigest() << std::endl;

//    sha512.update("AMOGUS");
//    std::cout << "SHA256(\"AMOGUS\") = " << sha512.hexDigest() << std::endl;

//    sha512.update("Продолжение приключений междуяхтовых сражений\n"
//                    "Началось в день после бури, когда встретил свой фрегат\n"
//                    "Пусть узнают гости моря всё владычество пирата!\n"
//                    "Кто владеет всем морем — настоящий тот пират!\n"
//                    "Грохот пушек, свист картечи, начат бой внезапной встречей\n"
//                    "Звон металла, пули, сабли — так идёт смертельный бой\n"
//                    "Повстречались два фрегата в синеве морского ада\n"
//                    "Наш пиратский корабль обернулся вам бедой!\n"
//                    "Наш пиратский корабль обернулся вам бедой!");
//    std::cout << "SHA512(UTF8 TEXT) = " << sha512.hexDigest() << std::endl;

//    infile.open("/home/d35ync/COPT/logo.xcf", std::ios::binary);
//    sha512.update(infile);
//    infile.close();
//    std::cout << "SHA512(FILE) = " << sha512.hexDigest() << std::endl;
}
