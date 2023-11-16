#include <iostream>

#include "../lib/encoding/base32.h"
#include "../lib/encoding/base64.h"


int main(int argc, char **argv)
{
    std::string inputStr;

    std::cout << "ENTER STRING> ";
    std::getline(std::cin, inputStr);

    std::string b64result = D35Crypto::Base64::encode(std::vector<uint8_t>(inputStr.begin(), inputStr.end()));
    std::string b32result = D35Crypto::Base32::encode(std::vector<uint8_t>(inputStr.begin(), inputStr.end()));

    std::cout << "Base64(" << inputStr << ") = " << b64result << std::endl;
    std::cout << "Base32(" << inputStr << ") = " << b32result << std::endl;

    std::vector<uint8_t> tmpBuffer;

    tmpBuffer = D35Crypto::Base64::decode(b64result);
    b64result = std::string(tmpBuffer.begin(), tmpBuffer.end());

    tmpBuffer = D35Crypto::Base32::decode(b32result);
    b32result = std::string(tmpBuffer.begin(), tmpBuffer.end());

    std::cout << "DEC_Base64() = " << b64result << std::endl;
    std::cout << "DEC_Base32() = " << b32result << std::endl;

    return 0;
}
