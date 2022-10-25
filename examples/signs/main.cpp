#include <iostream>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "../lib/hash/sha512.h"

#include "../lib/public_key/rsa.h"
#include "../lib/public_key/rsakey.h"

#include "../lib/public_key/elgamal.h"
#include "../lib/public_key/elgamalkey.h"

#include "../lib/public_key/fiatshamir.h"
#include "../lib/public_key/fiatshamirkey.h"

#include "../lib/encoding/cades.h"


void workServer();
void workClient();
void keygen();
// need rework
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

    if (args[0] == "--server")
    {
        workServer();
    }
    else if (args[0] == "--client")
    {
        workClient();
    }
}

int sendall(int sockfd, const std::vector<uint8_t> &data, int flags = 0)
{
    size_t len = data.size();

    char tmp[8];
    tmp[0] = len >> 56 & 0xFF;
    tmp[1] = len >> 48 & 0xFF;
    tmp[2] = len >> 40 & 0xFF;
    tmp[3] = len >> 32 & 0xFF;
    tmp[4] = len >> 24 & 0xFF;
    tmp[5] = len >> 16 & 0xFF;
    tmp[6] = len >> 8  & 0xFF;
    tmp[7] = len >> 0  & 0xFF;

    send(sockfd, tmp, 8, 0);

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

    return (n == -1 ? -1 : completed);
}

void recvall(int sockfd, std::vector<uint8_t> &buffer)
{
    uint8_t tmp[8] = {};
    buffer.clear();

    recv(sockfd, tmp, 8, 0);

    size_t len = (static_cast<size_t>(tmp[0]) << 56) |
                 (static_cast<size_t>(tmp[1]) << 48) |
                 (static_cast<size_t>(tmp[2]) << 40) |
                 (static_cast<size_t>(tmp[3]) << 32) |
                 (static_cast<size_t>(tmp[4]) << 24) |
                 (static_cast<size_t>(tmp[5]) << 16) |
                 (static_cast<size_t>(tmp[6]) << 8 ) |
                 (static_cast<size_t>(tmp[7]) << 0);

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
}

void workServer()
{
    const int enable = 1;
    int socketlisten = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    setsockopt(socketlisten, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
    if (socketlisten < 0)
    {
        std::cout << "Server: error socket\n";
        return;
    }

    struct sockaddr_in stSockAddr;

    stSockAddr.sin_family = AF_INET;
    stSockAddr.sin_port = htons(9583);
    stSockAddr.sin_addr.s_addr = INADDR_ANY;

    //
    if (bind(socketlisten, (const sockaddr*)&stSockAddr, sizeof(stSockAddr)) < 0)
    {
        std::cerr << "Server: Error bind\n";
        return;
    }
    else
    {
        std::cout << "Server: bind is ok\n";
    }

    if (listen(socketlisten, 1) < 0)
    {
        std::cout << "Server:error listen\n";
        return;
    }
    else
    {
        std::cout << "Server: listen\n";
    }

    int clientSocket = accept(socketlisten, NULL, NULL);

    std::vector<uint8_t> buffer;
    recvall(clientSocket, buffer);

    /// RSA

    D35Crypto::SHA512 sha;
    D35Crypto::RSA rsa;
    D35Crypto::RSAKey rsaPubKey = D35Crypto::RSAKey::fromPKCS8File("rsa.pub"); // client
    D35Crypto::CAdES cades = D35Crypto::CAdES::fromBytes(buffer);
    std::cout << "RSA SIGN INFO" << std::endl << cades << std::endl;
    if (rsa.checkSign(buffer, cades, rsaPubKey))
    {
        std::cout << "RSA SIGN CORRECT" << std::endl;
    }
    else
    {
        std::cerr << "RSA SIGN INCORRECT" << std::endl;
    }

    D35Crypto::RSAKey rsaKey = D35Crypto::RSAKey::fromPKCS12File("CA.rsa");
    rsaPubKey = D35Crypto::RSAKey::fromPKCS8File("CA.rsa.pub");

    sha.update(rsaPubKey.exportPublicKeyBytes());
    rsa.signCA(cades, sha.digest(), buffer, rsaKey);

    buffer = cades.toBytes();

    sendall(clientSocket, buffer);
    std::cout << std::endl << std::endl;

    /// ElGamal

    recvall(clientSocket, buffer);

    D35Crypto::ElGamal elGamal;
    D35Crypto::ElGamalKey egPubKey = D35Crypto::ElGamalKey::fromPKCS8File("elgamal.pub");
    cades = D35Crypto::CAdES::fromBytes(buffer);
    std::cout << "ELGAMAL SIGN INFO" << std::endl << cades << std::endl;
    if (elGamal.checkSign(buffer, cades, egPubKey))
    {
        std::cout << "ELGAMAL SIGN CORRECT" << std::endl;
    }
    else
    {
        std::cerr << "ELGAMAL SIGN INCORRECT" << std::endl;
    }

    D35Crypto::ElGamalKey egPrivKey = D35Crypto::ElGamalKey::fromPKCS12File("CA.elgamal");
    egPubKey = D35Crypto::ElGamalKey::fromPKCS8File("CA.elgamal.pub");

    sha.update(egPubKey.exportPublicKeyBytes());
    elGamal.signCA(cades, sha.digest(), buffer, egPrivKey);

    buffer = cades.toBytes();

    sendall(clientSocket, buffer);
    std::cout << std::endl << std::endl;

    /// FIAT SHAMIR

    recvall(clientSocket, buffer);

    D35Crypto::FiatShamir fs;
    D35Crypto::FiatShamirKey fsPubKey = D35Crypto::FiatShamirKey::fromPKCS8File("fs.pub");
    cades = D35Crypto::CAdES::fromBytes(buffer);
    std::cout << "FIAT-SHAMIR SIGN INFO" << std::endl << cades << std::endl;
    if (fs.checkSign(buffer, cades, fsPubKey))
    {
        std::cout << "FIAT-SHAMIR SIGN CORRECT" << std::endl;
    }
    else
    {
        std::cerr << "FIAT-SHAMIR SIGN INCORRECT" << std::endl;
    }

    D35Crypto::FiatShamirKey fsPrivKey = D35Crypto::FiatShamirKey::fromPKCS12File("CA.fs");
    fsPubKey = D35Crypto::FiatShamirKey::fromPKCS8File("CA.fs.pub");

    sha.update(fsPubKey.exportPublicKeyBytes());
    fs.signCA(cades, sha.digest(), buffer, fsPrivKey);

    buffer = cades.toBytes();

    sendall(clientSocket, buffer);

    ///

    close(clientSocket);
    close(socketlisten);

    printf("shutdown. server.\n");
}

void workClient()
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

    size_t fileSize = 0;
    std::ifstream infile;
    std::vector<uint8_t> buffer;
    std::vector<uint8_t> completeBuffer;

    D35Crypto::SHA512 sha;
    D35Crypto::RSA rsa;
    D35Crypto::RSAKey rsaPrivKey = D35Crypto::RSAKey::fromPKCS12File("rsa");
    D35Crypto::RSAKey rsaPubKey = D35Crypto::RSAKey::fromPKCS8File("rsa.pub");
    sha.update(rsaPubKey.exportPublicKeyBytes());
    D35Crypto::CAdES rsaCAdES = rsa.sign("D35YNC", sha.digest(), "IMAGE", "xka9otdz.jpg", &sha, rsaPrivKey);
    std::cout << "IMAGE SIGNED BY RSA" << std::endl << rsaCAdES << std::endl;

    buffer = rsaCAdES.toBytes();

    infile.open("xka9otdz.jpg", std::ios::binary);
    infile.seekg(0, std::ios::end);
    fileSize = infile.tellg();
    infile.seekg(0, std::ios::beg);
    completeBuffer.resize(fileSize + buffer.size());
    infile.read(reinterpret_cast<char*>(completeBuffer.data()), fileSize);
    infile.close();

    std::copy(buffer.begin(), buffer.end(), completeBuffer.begin() + fileSize);

    sendall(sockfd, completeBuffer);
    recvall(sockfd, buffer);

    std::cout << std::endl << "RECEIVED SIGN FROM CA" << std::endl;
    completeBuffer.resize(buffer.size() + fileSize);
    std::copy(buffer.begin(), buffer.end(), completeBuffer.begin() + fileSize);
    rsaCAdES = D35Crypto::CAdES::fromBytes(completeBuffer);
    if (rsa.checkSign(completeBuffer, rsaCAdES, rsaPubKey))
    {
        std::cout << "MY RSA SIGN CORRECT" << std::endl;
    }
    else
    {
        std::cerr << "MY RSA SIGN INCORRECT" << std::endl;
    }

    D35Crypto::RSAKey caRsaPubKey = D35Crypto::RSAKey::fromPKCS8File("CA.rsa.pub");
    if (rsa.checkCASign(completeBuffer, rsaCAdES, caRsaPubKey))
    {
        std::cout << "CA RSA SIGN CORRECT" << std::endl << "CA RSA SIGN INFO" << std::endl << rsaCAdES << std::endl;
    }
    else
    {
        std::cout << "CA RSA SIGN INCORRECT" << std::endl << "CA RSA SIGN INFO" << std::endl << rsaCAdES << std::endl;
    }

    std::cout << std::endl << std::endl;

    //#######################

    std::string egMessage = "Я текс, делаю вид что я сообщение которое нужно подписать. Легушки крутые";
    D35Crypto::ElGamal elGamal;
    D35Crypto::ElGamalKey egPrivKey = D35Crypto::ElGamalKey::fromPKCS12File("elgamal");
    D35Crypto::ElGamalKey egPubKey = D35Crypto::ElGamalKey::fromPKCS8File("elgamal.pub");
    sha.update(egPubKey.exportPublicKeyBytes());
    D35Crypto::CAdES egCAdES = elGamal.sign("D35YNC", sha.digest(), egMessage, &sha, egPrivKey);
    std::cout << "TEXT SIGNED BY ELGAMAl" << std::endl << egCAdES << std::endl;

    buffer = egCAdES.toBytes();

    completeBuffer.resize(egMessage.size() + buffer.size());
    std::copy(egMessage.begin(), egMessage.end(), completeBuffer.begin());
    std::copy(buffer.begin(), buffer.end(), completeBuffer.begin() + egMessage.size());

    sendall(sockfd, completeBuffer);
    recvall(sockfd, buffer);

    std::cout << std::endl << "RECEIVED SIGN FROM CA" << std::endl;
    completeBuffer.resize(buffer.size() + egMessage.size());
    std::copy(buffer.begin(), buffer.end(), completeBuffer.begin() + egMessage.size());
    egCAdES = D35Crypto::CAdES::fromBytes(completeBuffer);
    if (elGamal.checkSign(completeBuffer, egCAdES, egPubKey))
    {
        std::cout << "MY ELGAMAL SIGN CORRECT" << std::endl;
    }
    else
    {
        std::cerr << "MY ELGAMAL SIGN INCORRECT" << std::endl;
    }

    D35Crypto::ElGamalKey caEgPubKey = D35Crypto::ElGamalKey::fromPKCS8File("CA.elgamal.pub");
    if (elGamal.checkCASign(completeBuffer, egCAdES, caEgPubKey))
    {
        std::cout << "CA ELGAMAL SIGN CORRECT" << std::endl << "CA ELGAMAL SIGN INFO" << std::endl << egCAdES << std::endl;
    }
    else
    {
        std::cout << "CA ELGAMAL SIGN INCORRECT" << std::endl << "CA ELGAMAL SIGN INFO" << std::endl << egCAdES << std::endl;
    }

    std::cout << std::endl << std::endl;

//    //########################################

    D35Crypto::FiatShamir fs;
    D35Crypto::FiatShamirKey fsPrivKey = D35Crypto::FiatShamirKey::fromPKCS12File("fs");
    D35Crypto::FiatShamirKey fsPubKey = D35Crypto::FiatShamirKey::fromPKCS8File("fs.pub");
    sha.update(fsPubKey.exportPublicKeyBytes());
    D35Crypto::CAdES fsCAdES = fs.sign("D35YNC", sha.digest(), "DOC", "Kriptograficheskie_protokoly.doc", &sha, fsPrivKey);
    std::cout << "DOC SIGNED BY FIAT-SHAMIR" << std::endl << fsCAdES << std::endl;

    buffer = fsCAdES.toBytes();

    infile.open("Kriptograficheskie_protokoly.doc", std::ios::binary);
    infile.seekg(0, std::ios::end);
    fileSize = infile.tellg();
    infile.seekg(0, std::ios::beg);
    completeBuffer.resize(fileSize + buffer.size());
    infile.read(reinterpret_cast<char*>(completeBuffer.data()), fileSize);
    infile.close();

    std::copy(buffer.begin(), buffer.end(), completeBuffer.begin() + fileSize);

    sendall(sockfd, completeBuffer);
    recvall(sockfd, buffer);

    std::cout << std::endl << "RECEIVED SIGN FROM CA" << std::endl;
    completeBuffer.resize(buffer.size() + fileSize);
    std::copy(buffer.begin(), buffer.end(), completeBuffer.begin() + fileSize);
    fsCAdES = D35Crypto::CAdES::fromBytes(completeBuffer);
    if (fs.checkSign(completeBuffer, fsCAdES, fsPubKey))
    {
        std::cout << "MY FIAT-SHAMIR SIGN CORRECT" << std::endl;
    }
    else
    {
        std::cerr << "MY FIAT-SHAMIR SIGN INCORRECT" << std::endl;
    }

    D35Crypto::FiatShamirKey caFsPubKey = D35Crypto::FiatShamirKey::fromPKCS8File("CA.fs.pub");
    if (fs.checkCASign(completeBuffer, fsCAdES, caFsPubKey))
    {
        std::cout << "CA FIAT-SHAMIR SIGN CORRECT" << std::endl << "CA FIAT-SHAMIR SIGN INFO" << std::endl << fsCAdES << std::endl;
    }
    else
    {
        std::cout << "CA FIAT-SHAMIR SIGN INCORRECT" << std::endl << "CA FIAT-SHAMIR SIGN INFO" << std::endl << fsCAdES << std::endl;
    }

    close(sockfd);
}

void keygen()
{
    D35Crypto::SHA512 sha512;
    D35Crypto::RSAKey rsaKeypair = D35Crypto::RSAKey::generate(4096);
    sha512.update(rsaKeypair.exportPrivateKeyBytes());
    std::cout << "RSA PRIVKEY FINGERPRINT: " << sha512.hexDigest() << std::endl;
    sha512.update(rsaKeypair.exportPublicKeyBytes());
    std::cout << "RSA PUBKEY FINGERPRINT: " << sha512.hexDigest() << std::endl;
    std::vector<uint8_t> outbuffer = rsaKeypair.exportPrivateKey().toPem();
    std::ofstream outfile("rsa");
    outfile.write(reinterpret_cast<char*>(outbuffer.data()), outbuffer.size());
    outfile.flush();
    outfile.close();
    outbuffer = rsaKeypair.exportPublicKey().toPem();
    outfile.open("rsa.pub");
    outfile.write(reinterpret_cast<char*>(outbuffer.data()), outbuffer.size());
    outfile.flush();
    outfile.close();

    D35Crypto::ElGamalKey elGamalKeypair = D35Crypto::ElGamalKey::generate(1024);
    sha512.update(elGamalKeypair.exportPrivateKeyBytes());
    std::cout << "ELGAMAL PRIVKEY FINGERPRINT: " << sha512.hexDigest() << std::endl;
    sha512.update(elGamalKeypair.exportPublicKeyBytes());
    std::cout << "ELGAMAL PUBKEY FINGERPRINT: " << sha512.hexDigest() << std::endl;
    outbuffer = elGamalKeypair.exportPrivateKey().toPem();
    outfile.open("elgamal");
    outfile.write(reinterpret_cast<char*>(outbuffer.data()), outbuffer.size());
    outfile.flush();
    outfile.close();
    outbuffer = elGamalKeypair.exportPublicKey().toPem();
    outfile.open("elgamal.pub");
    outfile.write(reinterpret_cast<char*>(outbuffer.data()), outbuffer.size());
    outfile.flush();
    outfile.close();

    D35Crypto::FiatShamirKey fsKeypair = D35Crypto::FiatShamirKey::generate(1024, &sha512);
    sha512.update(fsKeypair.exportPrivateKeyBytes());
    std::cout << "FIAT-SHAMIR PRIVKEY FINGERPRINT: " << sha512.hexDigest() << std::endl;
    sha512.update(fsKeypair.exportPublicKeyBytes());
    std::cout << "FIAT-SHAMIR PUBKEY FINGERPRINT: " << sha512.hexDigest() << std::endl;
    outbuffer = fsKeypair.exportPrivateKey().toPem();
    outfile.open("fs");
    outfile.write(reinterpret_cast<char*>(outbuffer.data()), outbuffer.size());
    outfile.flush();
    outfile.close();
    outbuffer = fsKeypair.exportPublicKey().toPem();
    outfile.open("fs.pub");
    outfile.write(reinterpret_cast<char*>(outbuffer.data()), outbuffer.size());
    outfile.flush();
    outfile.close();
}
