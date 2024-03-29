#include <iostream>
#include <algorithm>
#include <iomanip>

#include "../lib/public_key/rsa.h"
#include "../lib/public_key/rsakey.h"

int main(int argc, char **argv)
{
    std::cout << "NOT IMPLEMENTED =(" << std::endl;
    return 0;

    std::cout << "Generating 4096 bit keypair ";

    D35Crypto::RSAKey keypair = D35Crypto::RSAKey::generate(4096);

    std::cout << "[OK]" << std::endl << "Writing privkey to key ";

    std::vector<uint8_t> buffer = keypair.exportPrivateKeyBytes();
    std::ofstream outfile("key");
    outfile.write(reinterpret_cast<char*>(buffer.data()), buffer.size());
    outfile.flush();
    outfile.close();

    std::cout << "[OK]" << std::endl << "Writing pubkey to key.pub ";

    buffer = keypair.exportPublicKeyBytes();
    outfile.open("key.pub");
    outfile.write(reinterpret_cast<char*>(buffer.data()), buffer.size());
    outfile.flush();
    outfile.close();

    std::cout << "[OK]" << std::endl << "Encrypting some data ";

    D35Crypto::RSAKey pubk = D35Crypto::RSAKey::publicKeyFromBytes({});

    std::cout << "[OK]" << std::endl;
    D35Crypto::RSA rsa;

    // Some 839 bytes Utf8 string
    buffer = {0xd0,0x92,0xd1,0x81,0xd0,0xb5,0xd0,0xbc,0x20,0xd0,0xbf,0xd1,0x80,0xd0,0xb8,0xd0,0xb2,0xd0,0xb5,0xd1,0x82,0x20,0xd0,0xbf,0xd0,0xbe,0xd0,0xb4,0xd0,0xbf,0xd0,0xb8,0xd1,0x81,0xd1,0x8b,0xd0,0xb2,0xd0,0xb0,0xd0,0xb9,0xd1,0x82,0xd0,0xb5,0xd1,0x81,0xd1,0x8c,0x20,0xd0,0xbd,0xd0,0xb0,0x20,0xd0,0xbd,0xd0,0xbe,0xd0,0xb2,0xd1,0x8b,0xd0,0xb9,0x20,0xd0,0xbf,0xd0,0xb0,0xd0,0xb1,0xd0,0xbb,0xd0,0xb8,0xd0,0xba,0x20,0xd0,0xbc,0xd0,0xb5,0xd0,0xbc,0xd1,0x8b,0x20,0xd0,0xbf,0xd1,0x80,0xd0,0xbe,0x20,0xd1,0x82,0xd0,0xb5,0xd0,0xbe,0xd1,0x80,0xd0,0xb8,0xd1,0x8e,0x20,0xd0,0xbf,0xd0,0xb8,0xd1,0x81,0xd1,0x82,0xd0,0xbe,0xd0,0xbb,0xd0,0xb5,0xd1,0x82,0xd0,0xbe,0xd0,0xb2,0x20,0xd0,0xbd,0xd0,0xbe,0xd0,0xb2,0xd1,0x8b,0xd0,0xb5,0x20,0x6d,0x65,0x6d,0x65,0x73,0x20,0xd0,0xba,0xd0,0xb0,0xd0,0xb6,0xd0,0xb4,0xd1,0x8b,0xd0,0xb9,0x20,0xd0,0xb4,0xd0,0xb5,0xd0,0xbd,0xd1,0x8c};

    buffer = rsa.encrypt(buffer, pubk);
    std::cout << "Writing encrypted data to data.enc ";
    outfile.open("data.enc");
    outfile.write(reinterpret_cast<char*>(buffer.data()), buffer.size());
    outfile.close();

    std::cout << "[OK]" << std::endl << "Loading privkey ";
    D35Crypto::RSAKey privk = D35Crypto::RSAKey::privateKeyFromBytes({});
    std::cout << "[OK]" << std::endl << "Decrypting data.enc";

    buffer = rsa.decrypt(buffer, privk);
    outfile.open("data.enc.dec");
    outfile.write(reinterpret_cast<char*>(buffer.data()), buffer.size());
    outfile.flush();
    outfile.close();
    std::cout << " [OK]" << std::endl << "END" << std::endl;

    return 0;
}
