#include <iostream>
#include <fstream>
#include <algorithm>

#include "../mycryptolib/encoding/base32.h"
#include "../mycryptolib/encoding/base64.h"

void usage()
{
    std::cout << "./lab2 {--base32 | --base64} {--encode | --decode} {--cin | --string [STRING] | --file [FILENAME]} [FILENAME]" << std::endl;
    exit(0);
}


int main(int argc, char **argv)
{
    // Arguments parsing
    const std::vector<std::string> avArgs = {"--base32", "--base64", "--encode", "--decode", "--cin", "--string", "--file"};
    std::vector<std::string> args;
    if (argc > 1)
    {
        args.assign(argv + 1, argv + argc);
    }
    else
    {
        usage();
    }

    int encodeMode = -1; // base32/64
    int workMode   = -1; // encode/decode
    int inputMode  = -1; // interactive/string/file
    bool nextIsParam = false;  // При трю - следующий args[i + 1] фактически не парсится тк уже был распраршен когда было установлено трю
    std::string tmpInputData   = ""; // INPUT_FILENAME if inputMode = 2; INPUT_STRING if inpmode = 1; std::getline if mode --cin = 0 after parsing
    std::string outputFilename = "./lab2_out";

    for (int i = 0; i < args.size(); i++)
    {
        if (nextIsParam)
        {
            nextIsParam = false;
            continue;
        }
        // Ищем iй аргумент внутри avArgs
        auto iter_ = std::find(avArgs.begin(), avArgs.end(), args[i]); // Да кто такой ваш итератор
        // Если он (iй) начинается с -- и содержится внутри avArgs то все норм
        if (args[i].rfind("--", 0) == 0 && iter_ != avArgs.end())
        {
            // Индекс аргумента в avArgs
            int index = iter_ - avArgs.begin();

            if (0 <= index && index < 2)
            {
                encodeMode = index;
                // 0 - Base32
                // 1 - Base64
            }
            else if (2 <= index && index < 4)
            {
                workMode = index - 2;
                // 0 == --encode
                // 1 == --decode
            }
            else if (4 <= index && index < avArgs.size())
            {
                inputMode = index - 4;
                // 0 == --cin
                // 1 == --string
                // 2 == --file

                if (inputMode > 0) // Для --string [DATA] и --file [DATA]
                {
                    // Забираем параметр для аргумента
                    if (i + 1 < args.size())
                    {
                        tmpInputData = args[i + 1];
                        nextIsParam = true;
                    }
                    else
                    {
                        usage(); // Тут выход при невозможности забрать параметр для аргумента
                    }
                }
            }
        }
        else
        {
            outputFilename = args[i];
        }
    }

    if (encodeMode == -1 || workMode == -1 || inputMode == -1)
    {
        usage();
    }


    std::vector<uint8_t> inputBuffer;
    if (inputMode == 0)
    {
        std::cout << "ENTER STRING> ";
        std::getline(std::cin, tmpInputData);
    }
    else if (inputMode == 2)
    {
        // Просто читаем все данные из файла tmpInputData в inputBuffer и закрываем файл
        std::ifstream inFile(tmpInputData, std::ios::binary);
        if (!inFile.is_open())
        {
            std::cout << "[ERROR] CNAT OPEN FILE " << tmpInputData << " FOR READ" << std::endl;
            exit(-1); // EXIT HERE ALRERT
        }
        size_t fileSize;

        inFile.seekg(0, std::ios::end);
        fileSize = inFile.tellg();
        inFile.seekg(0, std::ios::beg);

        inputBuffer.resize(fileSize);
        inFile.read((char*)(inputBuffer.data()), fileSize);
        inFile.close();
    }
    if (inputMode != 2)
    {
        // Если строка уже прочитана записать ее в inputBuffer
        inputBuffer.resize(tmpInputData.size());
        std::copy(tmpInputData.begin(), tmpInputData.end(), inputBuffer.begin());
    }

    std::vector<uint8_t> result;
    if (workMode == 0) // Encode
    {
        std::string result_str;

        if (encodeMode == 0) // Base32
        {
            result_str = MyCryptoLib::Base32::b32Encode(inputBuffer);
        }
        else // Base64
        {
            result_str = MyCryptoLib::Base64::b64Encode(inputBuffer);
        }
        result.resize(result_str.size());
        std::copy(result_str.begin(), result_str.end(), result.begin());
    }
    else // Decode
    {
        if (encodeMode == 0) // Base32
        {
            std::string x =std::string(inputBuffer.begin(), inputBuffer.end());
            result = MyCryptoLib::Base32::b32Decode(x);
        }
        else // Base64
        {
            result = MyCryptoLib::Base64::b64Decode(std::string(inputBuffer.begin(), inputBuffer.end()));
        }
    }

    if (result.size() == 0)
    {
        std::cout << "[ERROR] CANT ENCODE THIS DATA" << std::endl;
        exit(-1);
    }

    std::ofstream outFile(outputFilename, std::ios::binary | std::ios::out);
    outFile.write((char*)result.data(), result.size());
    outFile.flush();
    outFile.close();

    return 0;
}
