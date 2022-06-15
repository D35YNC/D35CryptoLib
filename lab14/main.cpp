#include <iostream>
#include <map>
#include <vector>
#include <string>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "../mycryptolib/hash/sha256.h"
#include "../mycryptolib/hash/sha512.h"
#include "../mycryptolib/hash/streebog.h"

void user_1();
void user_2();

static const std::vector<uint8_t> USER_1_ID = {0x14,0x28,0x23,0x5f,0x56,0x73,0x75,0xff,0x30,0x2a,0x8e,0x5c,0x07,0xb3,0x7a,0x13,0xcb,0x06,0xa8,0x06,0xed,0x58,0xa6,0x7f,0x64,0xf0,0xb1,0xca,0xaa,0x08,0xdc,0x7b};
static const std::vector<uint8_t> USER_2_ID = {0x9e,0xed,0x69,0x0d,0xbd,0xa3,0xd3,0xfc,0x29,0x63,0xe9,0x7a,0x2b,0x21,0x64,0x3c,0xa1,0x4b,0x85,0x77,0x94,0x39,0x37,0xff,0x95,0x03,0x77,0x5d,0xd8,0xa3,0xe4,0x79};

static const std::string USER_2_CLEAR_PWD = "#2cr&.ocW'}7^va!kd4y,@C(";

static int N = 100;

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


std::vector<std::vector<uint8_t>> precalc_hashes()
{
    MyCryptoLib::SHA512 hash;

    std::vector<std::vector<uint8_t>> digests(N, std::vector<uint8_t>());

    hash.update(USER_2_CLEAR_PWD);
    digests[0] = hash.digest();

    for (int i = 1; i < N; i++)
    {
        hash.update(digests[i - 1]);
        digests[i] = hash.digest();
    }

    return digests;
}


void user_1()
{
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
    //
    // Server Side
    //

    std::vector<std::vector<uint8_t>> digests = precalc_hashes();

    std::vector<uint8_t> buffer;

    recvall(opSocket, buffer);

    std::vector<uint8_t> opId(buffer.begin(), buffer.begin() + 32);
    std::vector<uint8_t> opI(buffer.begin() + 32, buffer.begin() + 36);
    std::vector<uint8_t> opAuth(buffer.begin() + 36, buffer.end());

    uint32_t i = static_cast<uint32_t>(opI[0] << 24) |
                 static_cast<uint32_t>(opI[1] << 16) |
                 static_cast<uint32_t>(opI[2] << 8 ) |
                 static_cast<uint32_t>(opI[3] << 0 );

    bool insideAuthorized = false;
    for (const std::pair<std::string, std::vector<uint8_t>> &user : AUTHORIZED_USERS)
    {
        if (user.second == opId)
        {
            insideAuthorized = true;
            std::cout << "USER FOUND: " << user.first << std::endl;
        }
    }
    if (!insideAuthorized)
    {
        std::cerr << "USER NOT IN AUTHORIZED USERS" << std::endl;
        buffer.resize(4);
        buffer[0] = 'B';
        buffer[1] = 'A';
        buffer[2] = 'D';
        buffer[3] = 'I';
        buffer[4] = 'D';
        sendall(opSocket, buffer);
        close(opSocket);
        return;
    }
    if (opAuth != digests[N - i])
    {
        std::cerr << "USER AUTH DATA INVALID" << std::endl;
        buffer.resize(11);
        buffer[0] = 'B';
        buffer[1] = 'A';
        buffer[2] = 'D';
        buffer[3] = 'A';
        buffer[4] = 'U';
        buffer[5] = 'T';
        buffer[6] = 'H';
        buffer[7] = 'D';
        buffer[8] = 'A';
        buffer[9] = 'T';
        buffer[10] = 'A';
        sendall(opSocket, buffer);
        sleep(1);
        close(opSocket);
        return;
    }

    std::cout << "AUTH SUCC" << std::endl;
    buffer.resize(9);

    buffer[0] = 'A';
    buffer[1] = 'U';
    buffer[2] = 'T';
    buffer[3] = 'O';
    buffer[4] = 'R';
    buffer[5] = 'I';
    buffer[6] = 'Z';
    buffer[7] = 'E';
    buffer[8] = 'D';

    sendall(opSocket, buffer);

    //#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

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

    //#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

    std::vector<std::vector<uint8_t>> digests = precalc_hashes();


    std::vector<uint8_t> myId(USER_2_ID.begin(), USER_2_ID.end());
    std::vector<uint8_t> myI = {0x00, 0x00, 0x00, 0x1A}; // 26
    std::vector<uint8_t> myAuth(digests[N - 0x1A].begin(), digests[N - 0x1A].end());

    std::vector<uint8_t> buffer(myId.size() + myI.size() + myAuth.size());
    std::copy(myId.begin(), myId.end(), buffer.begin());
    std::copy(myI.begin(), myI.end(), buffer.begin() + myId.size());
    std::copy(myAuth.begin(), myAuth.end(), buffer.end() - myAuth.size());

    sendall(sockfd, buffer);
    recvall(sockfd, buffer);

    std::cout << std::string(buffer.begin(), buffer.end()) << std::endl;

    //#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

    close(sockfd);
}
