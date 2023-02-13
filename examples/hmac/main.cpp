#include <iostream>

#include "../lib/hash/sha256.h"
#include "../lib/symmetric_key/key.h"
#include "../lib/hash/hmac.h"

int main(int argc, char **argv)
{
    D35Crypto::Key k = D35Crypto::Key::generate(128);
    std::cout << "HMACKING with key: " << k.hex() << std::endl;

    D35Crypto::HMAC<D35Crypto::SHA256> hmac;
    hmac.create("Som estring", k.raw());
    std::cout << hmac.name() << ' ' << hmac.hexDigest() << std::endl;
}
