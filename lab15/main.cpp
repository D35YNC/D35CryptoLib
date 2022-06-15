#include <iostream>
#include <map>
#include <vector>
#include <string>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <NTL/ZZ.h>
#include <random>

void ca();
void user_1();
void user_2();

static const std::vector<uint8_t> SECRET = {0xa5, 0xbf, 0x4a, 0x9c, 0xd4, 0x7b, 0x2e, 0x67, 0x00, 0xd3 };

int main(int argc, char **argv)
{
    if (argc < 1)
    {
        return 0;
    }

    std::vector<std::string> args;
    args.assign(argv + 1, argv + argc);

    if (args[0] == "-ca")
    {
        ca();
    }
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



void ca()
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

    int userA = accept(mySocket, NULL, NULL);
    int userB = accept(mySocket, NULL, NULL);

    //#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
    //
    // Server Side
    //


    std::cout << "#BEGIN" << std::endl;

    NTL::ZZ p = NTL::GenPrime_ZZ(512, 100);
    NTL::ZZ q = NTL::GenPrime_ZZ(512, 100);
    NTL::ZZ n = p * q;

    std::cout << "p = " << p << std::endl <<
                 "q = " << q << std::endl <<
                 "n = " << n << std::endl;

    std::vector<uint8_t> buffer(NTL::NumBytes(n), 0x00);
    NTL::BytesFromZZ(buffer.data(), n, buffer.size());
    sendall(userA, buffer);
    sendall(userB, buffer);

    // V
    recvall(userA, buffer);
    sendall(userB, buffer);

    for (int i = 0; i < 10; i++)
    {
        // X
        recvall(userA, buffer);
        sendall(userB, buffer);

        // C
        recvall(userB, buffer);
        sendall(userA, buffer);

        // Z,C=0;
        // ZS(MOD N),c=1
        recvall(userA, buffer);
        sendall(userB, buffer);
    }

    //#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

    close(userA);
    close(userB);
    close(mySocket);
}

void user_1() // A
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

    std::vector<uint8_t> buffer;

    recvall(sockfd, buffer);

    NTL::ZZ n = NTL::ZZFromBytes(buffer.data(), buffer.size());
    NTL::ZZ s = NTL::ZZFromBytes(SECRET.data(), SECRET.size());

    if (NTL::GCD(s, n) != NTL::conv<NTL::ZZ>(1))
    {
        std::cerr << "!1" << std::endl;
    }

    // V
    NTL::ZZ v = NTL::PowerMod(s, 2, n);
    std::cout << "v = " << v << std::endl;

    buffer.resize(NTL::NumBytes(v));
    NTL::BytesFromZZ(buffer.data(), v, buffer.size());
    sendall(sockfd, buffer);

    NTL::ZZ z;
    NTL::ZZ x;

    for (int i = 0; i < 10; i++)
    {
        std::cout << "ITER " << i << std::endl;
        z = NTL::RandomBnd(n);
        x = NTL::PowerMod(z, 2, n);

        std::cout << "SENDIN X" << std::endl;
        buffer.resize(NTL::NumBytes(x));
        NTL::BytesFromZZ(buffer.data(), x, buffer.size());
        sendall(sockfd, buffer);

        recvall(sockfd, buffer);
        std::cout << "C = " << (int)buffer[0] << std::endl;
        if (buffer[0] == 0x00)
        {
            buffer.resize(NTL::NumBytes(z));
            NTL::BytesFromZZ(buffer.data(), z, buffer.size());
            sendall(sockfd, buffer);
        }
        else
        {
            NTL::ZZ r = NTL::MulMod(z, s, n);
            buffer.resize(NTL::NumBytes(r));
            NTL::BytesFromZZ(buffer.data(), r, buffer.size());
            sendall(sockfd, buffer);
        }
    }


    //#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

    close(sockfd);
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

    std::vector<uint8_t> buffer;

    recvall(sockfd, buffer);
    NTL::ZZ n = NTL::ZZFromBytes(buffer.data(), buffer.size());

    recvall(sockfd, buffer);
    NTL::ZZ v = NTL::ZZFromBytes(buffer.data(), buffer.size());

    NTL::ZZ x;
    NTL::ZZ y;

    bool ok = true;
    for (int i = 0; i < 10; i++)
    {
        std::cout << "ITER " << i << std::endl;
        recvall(sockfd, buffer);
        x = NTL::ZZFromBytes(buffer.data(), buffer.size());
        std::cout << x << std::endl;

        uint8_t randVal = rand() % 2 == 0 ? 0x00 : 0xFF;
        std::cout << "rand = " << (int)randVal << std::endl;
        buffer.resize(1);
        buffer[0] = randVal;
        sendall(sockfd, buffer);

        recvall(sockfd, buffer);
        y = NTL::ZZFromBytes(buffer.data(), buffer.size());

        if (y != NTL::conv<int>(0) &&
                NTL::PowerMod(y, 2, n) == NTL::MulMod(x, NTL::PowerMod(v, randVal == 0 ? 0 : 1, n), n))
        {
            std::cout << "CHECK " << i + 1 << " OK" << std::endl;
        }
        else
        {
            ok = false;
            std::cout << "CHECK " << i + 1 << " NOT OK" << std::endl;
        }
    }

    if (ok)
    {
        std::cout << "ALL CHECKS OK" << std::endl;
    }
    else
    {
        std::cout << "NOT OK NOT OK" << std::endl;
    }

    //#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

    close(sockfd);
}
