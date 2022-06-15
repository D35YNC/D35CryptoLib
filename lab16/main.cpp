#include <iostream>
#include <map>
#include <vector>
#include <string>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "../mycryptolib/symmetric_key/key.h"
#include "../mycryptolib/public_key/rsa.h"
#include "../mycryptolib/public_key/rsakey.h"
#include "../mycryptolib/encoding/cades.h"
#include "../mycryptolib/hash/sha512.h"

void keygen();
void user_1();
void user_2();


static const std::vector<uint8_t> USER_1_ID = {0x14,0x28,0x23,0x5f,0x56,0x73,0x75,0xff,0x30,0x2a,0x8e,0x5c,0x07,0xb3,0x7a,0x13,0xcb,0x06,0xa8,0x06,0xed,0x58,0xa6,0x7f,0x64,0xf0,0xb1,0xca,0xaa,0x08,0xdc,0x7b};
static const std::vector<uint8_t> USER_2_ID = {0x9e,0xed,0x69,0x0d,0xbd,0xa3,0xd3,0xfc,0x29,0x63,0xe9,0x7a,0x2b,0x21,0x64,0x3c,0xa1,0x4b,0x85,0x77,0x94,0x39,0x37,0xff,0x95,0x03,0x77,0x5d,0xd8,0xa3,0xe4,0x79};


int main(int argc, char **argv)
{
//    keygen();
//    return 0;
    if (argc < 1)
    {
        return 0;
    }

    std::vector<std::string> args;
    args.assign(argv + 1, argv + argc);

    if (args[0] == "-u1")
    {
        user_1();
    }
    else if (args[0] == "-u2")
    {
        user_2();
    }
}

int sendall(int sockfd, const std::vector<uint8_t> &data, int flags = 0)
{
    size_t len = data.size();
    std::cout << "SENDIN " << len << " BYTES" << std::endl;
    uint8_t tmp[2];
    tmp[0] = len >> 8 & 0xFF;
    tmp[1] = len >> 0 & 0xFF;

    send(sockfd, tmp, 2, 0);

    int completed = 0;
    int n = -1;

    while (completed < len)
    {
        if (len - completed >= 4096)
        {
            n = send(sockfd, &data.data()[completed], 4096, flags);
        }
        else
        {
            n = send(sockfd, &data.data()[completed], len - completed, flags);
        }
        if (n == -1)
        {
            break;
        }
        completed += n;
    }
    std::cout << "SENDED " << completed << " BYTES" << std::endl;
    return (n == -1 ? -1 : completed);
}

void recvall(int sockfd, std::vector<uint8_t> &buffer)
{
    uint8_t tmp[2] = {0x00};
    recv(sockfd, tmp, 2, 0);
    uint16_t len = (static_cast<uint16_t>(tmp[0]) << 8) |
                   (static_cast<uint16_t>(tmp[1]) << 0);
    std::cout << "RECVIN " << len << " BYTES" << std::endl;
    buffer.clear();
    buffer.resize(len);

    int completed = 0;
    int n = -1;

    while (completed < len)
    {
        if (len - completed >= 4096)
        {
            n = recv(sockfd, &buffer.data()[completed], 4096, 0);
        }
        else
        {
            n = recv(sockfd, &buffer.data()[completed], len - completed, 0);
        }
        if (n == -1)
        {
            break;
        }
        completed += n;
    }
    std::cout << "RECVED " << completed << " BYTES" << std::endl;
}


void user_1()
{
    MyCryptoLib::RSAKey k = MyCryptoLib::RSAKey::generate(4096);
    std::ofstream keyfile("user2.key");
    std::vector<uint8_t> key = k.exportPrivateKey().toPem();
    keyfile.write(reinterpret_cast<char*>(key.data()), key.size());
    keyfile.flush();
    keyfile.close();

    keyfile.open("user2.key.pub");
    key = k.exportPublicKey().toPem();
    keyfile.write(reinterpret_cast<char*>(key.data()), key.size());
    keyfile.flush();
    keyfile.close();

    std::string myName = "D35YNC";
    const int enable = 1;
    int mySocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    setsockopt(mySocket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
    if (mySocket < 0)
    {
        std::cerr << "Error socket()" << std::endl;
        return;
    }

    struct sockaddr_in stSockAddr;

    stSockAddr.sin_family = AF_INET;
    stSockAddr.sin_port = htons(9583);
    stSockAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(mySocket, (const sockaddr*)&stSockAddr, sizeof(stSockAddr)) < 0)
    {
        std::cerr << "Error bind()" << std::endl;
        return;
    }
    else
    {
        std::cout << "Bind succ" << std::endl;
    }

    if (listen(mySocket, 1) < 0)
    {
        std::cout << "Error listen()" << std::endl;
        return;
    }
    else
    {
        std::cout << "Listen succ" << std::endl;
    }

    int opSocket = accept(mySocket, NULL, NULL);

    //#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

    MyCryptoLib::Key symKey = MyCryptoLib::Key::generate(256);

    std::cout << symKey.rawString() << std::endl;

    std::vector<uint8_t> symKeyBytes = symKey.raw();

    MyCryptoLib::RSA rsa;
    MyCryptoLib::SHA512 sha;
    MyCryptoLib::RSAKey myPrivkey = MyCryptoLib::RSAKey::fromPKCS12File("user1_key");
    MyCryptoLib::RSAKey myPubkey = MyCryptoLib::RSAKey::fromPKCS8File("user1_key.pub");
    MyCryptoLib::RSAKey opPubkey = MyCryptoLib::RSAKey::fromPKCS8File("user2_key.pub");

    std::vector<uint8_t> signBytes(USER_2_ID.size() + symKey.size());
    std::copy(USER_2_ID.begin(), USER_2_ID.end(), signBytes.begin());
    std::copy(symKeyBytes.begin(), symKeyBytes.end(), signBytes.end() - symKey.size());

    sha.update(myPubkey.exportPublicKeyBytes());

    MyCryptoLib::CAdES sign = rsa.sign("D35YNC", sha.digest(), "RAW", signBytes, &sha, myPrivkey);
    signBytes = sign.toBytes();

    std::vector<uint8_t> encBytes(symKey.size() + signBytes.size());
    std::copy(symKeyBytes.begin(), symKeyBytes.end(), encBytes.begin());
    std::copy(signBytes.begin(), signBytes.end(), encBytes.end() - signBytes.size());

    encBytes = rsa.encrypt(encBytes, opPubkey);

    sendall(opSocket, encBytes);

    //#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

    close(opSocket);
    close(mySocket);
}

void user_2() // B
{
    // Generating 512 bytes seed
    std::vector<unsigned char> seed(512, 0x00);
    std::uniform_int_distribution<uint64_t> dist(0, UINT64_MAX - 1);
    std::random_device dev_random("/dev/random");
    for (int i = 0; i < seed.size(); i++)
    {
        seed[i] = dist(dev_random);
    }
    NTL::SetSeed(seed.data(), seed.size());


    int sockfd;
    struct sockaddr_in addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        std::cerr << "cant create socket" << std::endl;
        return;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(9583);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        std::cerr << "Connecting error" << std::endl;
        return;
    }

    //#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

    std::vector<uint8_t> encBytes;
    recvall(sockfd, encBytes);

    MyCryptoLib::RSA rsa;
    MyCryptoLib::SHA512 sha;
    MyCryptoLib::RSAKey opPubkey = MyCryptoLib::RSAKey::fromPKCS8File("user1_key.pub");
    MyCryptoLib::RSAKey myPrivkey = MyCryptoLib::RSAKey::fromPKCS12File("user2_key");

    std::vector<uint8_t> decBytes = rsa.decrypt(encBytes, myPrivkey);
//    std::vector<uint8_t> keyBytes(decBytes.begin(), decBytes.begin() + 32);
//    std::vector<uint8_t> signBytes(decBytes.begin() + 32, decBytes.end());

    MyCryptoLib::CAdES cades = MyCryptoLib::CAdES::fromBytes(decBytes);

//    std::vector<uint8_t> signCheckBytes(USER_2_ID.size() + keyBytes.size());
//    std::copy(USER_2_ID.begin(), USER_2_ID.end(), signBytes.begin());
//    std::copy(keyBytes.begin(), keyBytes.end(), signBytes.end() - keyBytes.size());

    if (rsa.checkSign({}, cades, opPubkey))
    {
        std::cout << "SIGN CORRECT" << std::endl;
        MyCryptoLib::Key k(std::vector<uint8_t>(decBytes.begin(), decBytes.begin() + 32));
        std::cout << k.rawString() << std::endl;
    }



    //#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

    close(sockfd);
}

void keygen()
{
    MyCryptoLib::RSAKey k = MyCryptoLib::RSAKey::generate(4096);
    std::vector<uint8_t> buffer = k.exportPrivateKey().toPem();
    std::ofstream keyfile("user1_key");
    keyfile.write(reinterpret_cast<char*>(buffer.data()), buffer.size());
    keyfile.flush();
    keyfile.close();

    buffer = k.exportPublicKey().toPem();
    keyfile.open("user1_key.pub");
    keyfile.write(reinterpret_cast<char*>(buffer.data()), buffer.size());
    keyfile.flush();
    keyfile.close();

    k = MyCryptoLib::RSAKey::generate(4096);
    buffer = k.exportPrivateKey().toPem();
    keyfile.open("user2_key");
    keyfile.write(reinterpret_cast<char*>(buffer.data()), buffer.size());
    keyfile.flush();
    keyfile.close();

    buffer = k.exportPublicKey().toPem();
    keyfile.open("user2_key.pub");
    keyfile.write(reinterpret_cast<char*>(buffer.data()), buffer.size());
    keyfile.flush();
    keyfile.close();
}
