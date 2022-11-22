#include <iostream>

#include "../lib/symmetric_key/rc4.h"
#include "../lib/symmetric_key/key.h"

int main(int argc, char **argv)
{

    D35Crypto::Key k = D35Crypto::Key::generate(256);
    std::cout << k.hex() << std::endl;

    std::string data = "sussy baka";

    D35Crypto::RC4 rc4enc(k);
    std::vector<uint8_t> enc_data = rc4enc.encrypt(std::vector<uint8_t>(data.begin(), data.end()));

    std::stringstream ss;
    ss << std::setfill('0') << std::hex;

    for (int i = 0; i < enc_data.size(); i++)
    {
        ss << std::setw(2) << static_cast<unsigned int>(enc_data[i]);
    }

    std::cout << ss.str() << std::endl << std::endl;

    D35Crypto::RC4 rc4dec(k);
    enc_data = rc4dec.decrypt(enc_data);
    for (int i = 0; i < enc_data.size(); i++)
    {
        std::cout << enc_data[i];
    }
    std::cout << std::endl;

    return 0;
}
