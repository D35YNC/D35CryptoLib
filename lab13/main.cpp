#include <iostream>
#include <map>
#include <vector>
#include <string>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "../mycryptolib/public_key/rsa.h"
#include "../mycryptolib/public_key/rsakey.h"

void user_1();
void user_2();

static const std::vector<uint8_t> USER_1_ID = {0x14,0x28,0x23,0x5f,0x56,0x73,0x75,0xff,0x30,0x2a,0x8e,0x5c,0x07,0xb3,0x7a,0x13,0xcb,0x06,0xa8,0x06,0xed,0x58,0xa6,0x7f,0x64,0xf0,0xb1,0xca,0xaa,0x08,0xdc,0x7b};
static const std::vector<uint8_t> USER_2_ID = {0x9e,0xed,0x69,0x0d,0xbd,0xa3,0xd3,0xfc,0x29,0x63,0xe9,0x7a,0x2b,0x21,0x64,0x3c,0xa1,0x4b,0x85,0x77,0x94,0x39,0x37,0xff,0x95,0x03,0x77,0x5d,0xd8,0xa3,0xe4,0x79};

static const std::vector<uint8_t> USER_ID_TERMINATOR = {0x1E, 0x0D, 0x1E, 0x0D, 0xFF, 0xFF, 0xFF, 0xFF};

static const std::map<std::string, std::vector<uint8_t>> AUTHORIZED_USERS = { { "D35YNC",    USER_1_ID },
                                                                              { "TROLLFACE", USER_2_ID } };

int main(int argc, char **argv)
{
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

    std::vector<uint8_t> myRandom(8, 0x00);
    std::vector<uint8_t> buffer(8, 0x00);
    std::vector<uint8_t> encBuffer;
    std::vector<uint8_t> completeBuffer;

    srand(time(nullptr));
    buffer[0] = myRandom[0] = rand() & 0xFF; // Представим что это рандом нумбер
    buffer[1] = myRandom[1] = rand() & 0xFF;
    buffer[2] = myRandom[2] = rand() & 0xFF;
    buffer[3] = myRandom[3] = rand() & 0xFF;
    buffer[4] = myRandom[4] = rand() & 0xFF;
    buffer[5] = myRandom[5] = rand() & 0xFF;
    buffer[6] = myRandom[6] = rand() & 0xFF;
    buffer[7] = myRandom[7] = rand() & 0xFF;

    buffer.resize(USER_1_ID.size() + 8);
    std::copy(USER_1_ID.begin(), USER_1_ID.end(), buffer.begin() + 8);

    MyCryptoLib::SHA512 sha;
    sha.update(buffer);
    std::vector<uint8_t> bufferDigest = sha.digest();

    MyCryptoLib::RSA rsa;
    k = MyCryptoLib::RSAKey::fromPKCS8File("user2.key.pub");

    buffer = rsa.encrypt(buffer, k);

    completeBuffer.resize(bufferDigest.size() + buffer.size() + 4);
    completeBuffer[0] = 0x01;
    completeBuffer[1] = 0x0A;
    completeBuffer[2] = 0xFF;
    completeBuffer[3] = 0x00;

    std::copy(bufferDigest.begin(), bufferDigest.end(), completeBuffer.begin() + 4);
    std::copy(buffer.begin(), buffer.end(), completeBuffer.begin() + 4 + bufferDigest.size());

    sendall(opSocket, completeBuffer);
    recvall(opSocket, completeBuffer);

    if (!(completeBuffer[0] == 0x01 &&
          completeBuffer[1] == 0x0A &&
          completeBuffer[2] == 0xFF &&
          completeBuffer[3] == 0x00))
    {
        std::cerr << "RECVED INVALID HEADER" << std::endl;
        close(opSocket);
        close(mySocket);
        return;
    }

    if (completeBuffer[4] == myRandom[0] &&
        completeBuffer[5] == myRandom[1] &&
        completeBuffer[6] == myRandom[2] &&
        completeBuffer[7] == myRandom[3] &&
        completeBuffer[8] == myRandom[4] &&
        completeBuffer[9] == myRandom[5] &&
        completeBuffer[10] == myRandom[6] &&
        completeBuffer[11] == myRandom[7])
    {
        std::cout << "RECEIVED VALID RANDOM" << std::endl;
    }

    close(opSocket);
    close(mySocket);
}

void user_2()
{
    int sockfd;
    struct sockaddr_in addr;
    std::string myName = "TROLLFACE";
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


    std::vector<uint8_t> buffer;
    std::vector<uint8_t> encBuffer;
    std::vector<uint8_t> completeBuffer;

    MyCryptoLib::SHA512 sha;
    MyCryptoLib::RSA rsa;
    MyCryptoLib::RSAKey k = MyCryptoLib::RSAKey::fromPKCS12File("user2.key");

    recvall(sockfd, completeBuffer);

    if (!(completeBuffer[0] == 0x01 &&
          completeBuffer[1] == 0x0A &&
          completeBuffer[2] == 0xFF &&
          completeBuffer[3] == 0x00))
    {
        std::cerr << "RECVED INVALID HEADER" << std::endl;
        close(sockfd);
        return;
    }

    buffer = std::vector<uint8_t>(completeBuffer.begin() + 4, completeBuffer.begin() + 4 + sha.digestSize());
    encBuffer = std::vector<uint8_t>(completeBuffer.begin() + 4 + sha.digestSize(), completeBuffer.end());

    completeBuffer = rsa.decrypt(encBuffer, k);

    sha.update(completeBuffer);
    if (buffer == sha.digest())
    {
        std::cout << "HASH CORRECT" << std::endl;
    }

    buffer.resize(12);
    buffer[0] = 0x01;
    buffer[1] = 0x0A;
    buffer[2] = 0xFF;
    buffer[3] = 0x00;
    std::copy(completeBuffer.begin(), completeBuffer.begin() + 8, buffer.begin() + 4);

    completeBuffer.erase(completeBuffer.begin(), completeBuffer.begin() + 8);

    if (AUTHORIZED_USERS.at(myName) == completeBuffer)
    {
        std::cerr << "I RECVED MY ID, ITS A TRAP" << std::endl;
        close(sockfd);
        return;
    }
    bool succ = false;
    for (const std::pair<std::string, std::vector<uint8_t>> &user : AUTHORIZED_USERS)
    {
        if (user.second == completeBuffer)
        {
            std::cout << "ID ACCEPTED. ITS " << user.first << std::endl;
            succ = true;
        }
    }
    if (!succ)
    {
        std::cerr << "USER NOT AUTHORIZED" << std::endl;
        close(sockfd);
        return;
    }

    sendall(sockfd, buffer);

    close(sockfd);
}
