#include <iostream>
#include <vector>
#include <string>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <NTL/ZZ.h>

/*
HOW TO RUN&CHECK
1. COMPILE
2. RUN ./lab19 -ca
3. RUN ./lab19 -u
4. RUN ./lab19 -u

LAST NUMBER IN OUTPUT IS SECRET KEY IN DEC ViEW

*/

void ca();
void user();
NTL::ZZ calc_session_key(const NTL::ZZ &p, const std::vector<NTL::ZZ> &privateid, const std::vector<NTL::ZZ> &publicid);
std::vector<std::vector<NTL::ZZ>> gen_matrix(unsigned int size, const NTL::ZZ &p);
std::vector<NTL::ZZ> gen_user_pubkey(unsigned int size, const NTL::ZZ &p);
std::vector<NTL::ZZ> gen_user_privkey(const std::vector<std::vector<NTL::ZZ>> &matrix, const std::vector<NTL::ZZ> pubkey, const NTL::ZZ &p);


NTL::ZZ calc_session_key(const NTL::ZZ &p, const std::vector<NTL::ZZ> &privateid, const std::vector<NTL::ZZ> &publicid)
{
    NTL::ZZ key;
    for (int i = 0; i < privateid.size(); i++)
    {
        NTL::MulAddTo(key, privateid[i], publicid[i]);
    }
    return key % p;
}

std::vector<std::vector<NTL::ZZ>> gen_matrix(unsigned int size, const NTL::ZZ &p)
{
    std::vector<std::vector<NTL::ZZ>> matrix(size);

    for (int i = 0; i < size; i++)
    {
        matrix[i].resize(size);
    }

    for (int i = 0; i < size; i++)
    {
        for (int j = 0; j < size; j++)
        {
            matrix[i][j] = NTL::RandomBnd(p);
        }
    }

    for (int i = 0; i < size; i++)
    {
        for (int j = 0; j < size; j++)
        {
            matrix[i][j] = matrix[j][i];
        }
    }

    return matrix;
}

std::vector<NTL::ZZ> gen_user_pubkey(unsigned int size, const NTL::ZZ &p)
{
    std::vector<NTL::ZZ> matrix(size);
    for (int i = 0; i < size; i++)
    {
        matrix[i] = NTL::RandomBnd(p);
    }
    return matrix;
}

std::vector<NTL::ZZ> gen_user_privkey(const std::vector<std::vector<NTL::ZZ>> &matrix, const std::vector<NTL::ZZ> pubkey, const NTL::ZZ &p)
{
    std::vector<NTL::ZZ> privkey(pubkey.size());
    NTL::ZZ tmp(0);
    for (int i = 0; i < matrix.size(); i++)
    {
        for (int j = 0; j < pubkey.size(); j++)
        {
            tmp += matrix[i][j] * pubkey[j];
        }
        privkey[i] = tmp % p;
        tmp = 0;
    }
    return privkey;
}


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
    else if (args[0] == "-u")
    {
        user();
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

    int u1socket = accept(mySocket, NULL, NULL);
    int u2socket = accept(mySocket, NULL, NULL);

    //#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

    int size = 10;
    NTL::ZZ p = NTL::GenPrime_ZZ(1024);

    // private matrix
    std::vector<std::vector<NTL::ZZ>> matrix = gen_matrix(size, p);

    std::vector<NTL::ZZ> A_PUB = gen_user_pubkey(size, p);
    std::vector<NTL::ZZ> B_PUB = gen_user_pubkey(size, p);

    std::vector<NTL::ZZ> A_PRIV = gen_user_privkey(matrix, A_PUB, p);
    std::vector<NTL::ZZ> B_PRIV = gen_user_privkey(matrix, B_PUB, p);


    // SEND A_PRIVKEY & B_PUBKEY TO A
    std::vector<uint8_t> buffer;

    buffer.resize(NTL::NumBytes(p));
    NTL::BytesFromZZ(buffer.data(), p, buffer.size());
    sendall(u1socket, buffer);

    for (int i = 0; i < A_PRIV.size(); i++)
    {
        buffer.resize(NTL::NumBytes(A_PRIV[i]));
        NTL::BytesFromZZ(buffer.data(), A_PRIV[i], buffer.size());
        sendall(u1socket, buffer);
    }
    for (int i = 0; i < B_PUB.size(); i++)
    {
        buffer.resize(NTL::NumBytes(B_PUB[i]));
        NTL::BytesFromZZ(buffer.data(), B_PUB[i], buffer.size());
        sendall(u1socket, buffer);
    }

    // SEND B_PRIVKEY & A_PUBKEY TO B

    buffer.resize(NTL::NumBytes(p));
    NTL::BytesFromZZ(buffer.data(), p, buffer.size());
    sendall(u2socket, buffer);

    for (int i = 0; i < B_PRIV.size(); i++)
    {
        buffer.resize(NTL::NumBytes(B_PRIV[i]));
        NTL::BytesFromZZ(buffer.data(), B_PRIV[i], buffer.size());
        sendall(u2socket, buffer);
    }
    for (int i = 0; i < A_PUB.size(); i++)
    {
        buffer.resize(NTL::NumBytes(A_PUB[i]));
        NTL::BytesFromZZ(buffer.data(), A_PUB[i], buffer.size());
        sendall(u2socket, buffer);
    }

    //#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

    close(u1socket);
    close(u2socket);
    close(mySocket);
}

void user()
{
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

    int size = 10;
    NTL::ZZ p;
    std::vector<NTL::ZZ> MY_PRIVKEY(size);
    std::vector<NTL::ZZ> OTHER_PUBKEY(size);
    std::vector<uint8_t> buffer;

    recvall(sockfd, buffer);
    p = NTL::ZZFromBytes(buffer.data(), buffer.size());

    // RECV OWN PRIVKEY
    for (int i = 0; i < size; i++)
    {
        recvall(sockfd, buffer);
        MY_PRIVKEY[i] = NTL::ZZFromBytes(buffer.data(), buffer.size());
    }

    // RECV OTHER PUBKEY
    for (int i = 0; i < size; i++)
    {
        recvall(sockfd, buffer);
        OTHER_PUBKEY[i] = NTL::ZZFromBytes(buffer.data(), buffer.size());
    }

    std::cout << calc_session_key(p, MY_PRIVKEY, OTHER_PUBKEY) << std::endl;

    //#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

    close(sockfd);
}

