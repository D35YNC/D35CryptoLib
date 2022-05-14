#include <iostream>

#include "../mycryptolib/hash/streebog.h"

void usage()
{
    std::cout << "Usage: lab4 {--digest (256 or 512)} { --cin | --file FILENAME | --string VALUE }" << std::endl;
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
    int inputMode = -1; //interactive/string/file
    bool nextIsParam = false;  // При трю - следующий args[i + 1] фактически не парсится тк уже был распраршен когда было установлено трю
    std::string inputData; // Filename if inputMode = 2; String to encode if inpmode = 1; std::getline if mode --cin = 0 after parsing

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
                    // ДА я обернул это в try katch
                    // А что?

                    // анек

/*
Позвал СЕО на работу трех программистов: Мидла, Сеньора и Джуна. И сказал он им,
у кого программа не будет вылетать, того возьмут на работу.
Мидл сел, пахал три дня, отрефакторил весь код, оптимизировал все функции, нормализовал
базы данных, все отлично и быстро работает. Сел CEO работать всё отлично, годно, а тут
бац - эксепшен! Уволили мидла.
Сеньор добавил нейросетей в распознавание функций ввода, чтобы программа сама на лету
проверяла ошибки пользователей и исправляла. CEO проверяет, всё отлично, а тут бац - эксепшен,
ошибка ввода. Уволили сеньора.
Джун запускает программу. CEO давай её тестить. Пыхтит, ищет ошибку- программа работает,
не крашится. Зовёт крутого тестера, вместе пыхтят, всякую ерунду в программу вводят - программа
работает. Говорит, ладно победил, скажи, почему твоя программа никогда не падает?
Джун - а где ей падать? Там весь проект в Try-Catch обернут!
*/

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
    if ((digestSize != 256 && digestSize != 512) || inputMode == -1)
    {
        usage();
    }

    MyCryptoLib::Streebog streebog;

    if (digestSize == 256)
    {
        streebog.setMode(256);
    }
    else
    {
        streebog.setMode(512);
    }

    if (inputMode == 2)
    {
        std::ifstream inFile(inputData);
        streebog.update(inFile);
    }
    else
    {
        streebog.update(inputData);
    }
    std::cout << streebog.hexDigest();


//    MyCryptoLib::Streebog streebog;
//    streebog.update("Киберкарась");
//    std::cout << "STREEBOG512(\"Киберкарась\") = " << streebog.hexDigest() << std::endl;

//    streebog.update("AMOGUS");
//    std::cout << "STREEBOG512(\"AMOGUS\") = " << streebog.hexDigest() << std::endl;

//    streebog.update("Продолжение приключений междуяхтовых сражений\n"
//                    "Началось в день после бури, когда встретил свой фрегат\n"
//                    "Пусть узнают гости моря всё владычество пирата!\n"
//                    "Кто владеет всем морем — настоящий тот пират!\n"
//                    "Грохот пушек, свист картечи, начат бой внезапной встречей\n"
//                    "Звон металла, пули, сабли — так идёт смертельный бой\n"
//                    "Повстречались два фрегата в синеве морского ада\n"
//                    "Наш пиратский корабль обернулся вам бедой!\n"
//                    "Наш пиратский корабль обернулся вам бедой!");
//    std::cout << "STREEBOG512(UTF8 TEXT) = " << streebog.hexDigest() << std::endl;

//    streebog.update(std::vector<uint8_t>{ 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32 });
//    std::cout << "STREEBOG512(TEST DATA 1)(NORMALIZED) = " << streebog.hexDigest() << std::endl;

//    streebog.update(std::vector<uint8_t>{ 0xd1, 0xe5, 0x20, 0xe2, 0xe5, 0xf2, 0xf0, 0xe8, 0x2c, 0x20, 0xd1, 0xf2, 0xf0, 0xe8, 0xe1, 0xee,0xe6,0xe8,0x20,0xe2,0xed,0xf3,0xf6,0xe8,0x2c,0x20,0xe2,0xe5, 0xfe, 0xf2, 0xfa, 0x20, 0xf1, 0x20, 0xec, 0xee, 0xf0, 0xff, 0x20, 0xf1, 0xf2, 0xf0, 0xe5, 0xeb, 0xe0, 0xec, 0xe8, 0x20, 0xed, 0xe0, 0x20, 0xf5, 0xf0, 0xe0, 0xe1, 0xf0, 0xfb, 0xff, 0x20, 0xef, 0xeb, 0xfa, 0xea, 0xfb, 0x20, 0xc8, 0xe3, 0xee, 0xf0, 0xe5, 0xe2, 0xfb });
//    std::cout << "STREEBOG512(TEST DATA 2)(NORMALIZED) = " << streebog.hexDigest() << std::endl;

//    std::ifstream infile("/home/d35ync/COPT/logo.xcf", std::ios::binary);
//    streebog.update(infile);
//    infile.close();
//    std::cout << "STREEBOG256(FILE) = " << streebog.hexDigest() << std::endl;


//    //s256
//    streebog.setMode(256);

//    streebog.update("Киберкарась");
//    std::cout << "STREEBOG256(\"Киберкарась\") = " << streebog.hexDigest() << std::endl;

//    streebog.update("AMOGUS");
//    std::cout << "STREEBOG256(\"AMOGUS\") = " << streebog.hexDigest() << std::endl;

//    streebog.update("Продолжение приключений междуяхтовых сражений\n"
//                    "Началось в день после бури, когда встретил свой фрегат\n"
//                    "Пусть узнают гости моря всё владычество пирата!\n"
//                    "Кто владеет всем морем — настоящий тот пират!\n"
//                    "Грохот пушек, свист картечи, начат бой внезапной встречей\n"
//                    "Звон металла, пули, сабли — так идёт смертельный бой\n"
//                    "Повстречались два фрегата в синеве морского ада\n"
//                    "Наш пиратский корабль обернулся вам бедой!\n"
//                    "Наш пиратский корабль обернулся вам бедой!");
//    std::cout << "STREEBOG256(UTF8 TEXT) = " << streebog.hexDigest() << std::endl;

//    streebog.update(std::vector<uint8_t>{ 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32 });
//    std::cout << "STREEBOG256(TEST DATA 1)(NORMALIZED) = " << streebog.hexDigest() << std::endl;

//    streebog.update(std::vector<uint8_t>{ 0xd1, 0xe5, 0x20, 0xe2, 0xe5, 0xf2, 0xf0, 0xe8, 0x2c, 0x20, 0xd1, 0xf2, 0xf0, 0xe8, 0xe1, 0xee,0xe6,0xe8,0x20,0xe2,0xed,0xf3,0xf6,0xe8,0x2c,0x20,0xe2,0xe5, 0xfe, 0xf2, 0xfa, 0x20, 0xf1, 0x20, 0xec, 0xee, 0xf0, 0xff, 0x20, 0xf1, 0xf2, 0xf0, 0xe5, 0xeb, 0xe0, 0xec, 0xe8, 0x20, 0xed, 0xe0, 0x20, 0xf5, 0xf0, 0xe0, 0xe1, 0xf0, 0xfb, 0xff, 0x20, 0xef, 0xeb, 0xfa, 0xea, 0xfb, 0x20, 0xc8, 0xe3, 0xee, 0xf0, 0xe5, 0xe2, 0xfb });
//    std::cout << "STREEBOG256(TEST DATA 2)(NORMALIZED) = " << streebog.hexDigest() << std::endl;

//    infile.open("/home/d35ync/COPT/logo.xcf", std::ios::binary);
//    streebog.update(infile);
//    infile.close();
//    std::cout << "STREEBOG256(FILE) = " << streebog.hexDigest() << std::endl;
}
