#include <iostream>
#include <algorithm>

#include "../mycryptolib/public_key/elgamal.h"
#include "../mycryptolib/public_key/elgamalkey.h"

void usage()
{
    std::cout << "Usage: lab5 {--digest (256 or 512)} { --cin | --file FILENAME | --string VALUE }" << std::endl;
    exit(0);
}

int main(int argc, char **argv)
{
    MyCryptoLib::ElGamal elGamal;

//    MyCryptoLib::ElGamalKey k = MyCryptoLib::ElGamalKey::generate(1024);


//  Arguments parsing
//    const std::vector<std::string> avArgs = {"--digest", "--cin", "--string", "--file"};
//    std::vector<std::string> args;
//    if (argc > 1)
//    {
//        args.assign(argv + 1, argv + argc);
//    }
//    else
//    {
//        usage();
//    }

//    int digestSize = -1; // disgest size
//    int inputMode = -1; //interactive/string/file
//    bool nextIsParam = false;  // При трю - следующий args[i + 1] фактически не парсится тк уже был распраршен когда было установлено трю
//    std::string inputData; // Filename if inputMode = 2; String to encode if inpmode = 1; std::getline if mode --cin = 0 after parsing

//    for (int i = 0; i < args.size(); i++)
//    {
//        if (nextIsParam)
//        {
//            nextIsParam = false;
//            continue;
//        }
//        auto iter_ = std::find(avArgs.begin(), avArgs.end(), args[i]); // Да кто такой ваш итератор
//        if (args[i].rfind("--", 0) == 0 && iter_ != avArgs.end())
//        {
//            // Это аргумент cmd
//            // и он разренеше

//            int index = iter_ - avArgs.begin();

//            if (index == 0)
//            {
//                try
//                {
//                    if (i + 1 < args.size())
//                    {
//                        digestSize = std::stoi(args[i + 1]);
//                        nextIsParam = true;
//                    }
//                    else
//                    {
//                        usage(); // Тут выход при невозможности забрать параметр для аргумента
//                    }
//                }
//                catch (std::invalid_argument)
//                {
//                    std::cerr << "Digest size must be int" << std::endl;
//                    usage();
//                }
//            }
//            else if (0 < index && index < avArgs.size())
//            {
//                inputMode = index - 1;
//                // 0 == --cin
//                // 1 == --string
//                // 2 == --file

//                if (inputMode > 0)
//                {
//                    if (i + 1 < args.size())
//                    {
//                        inputData = args[i + 1];
//                        nextIsParam = true;
//                    }
//                    else
//                    {
//                        usage(); // Тут выход при невозможности забрать параметр для аргумента
//                    }
//                }
//            }
//        }
//    }

//    if ((digestSize != 256 && digestSize != 512) || inputMode == -1)
//    {
//        usage();
//    }
}

