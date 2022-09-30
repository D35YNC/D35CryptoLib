#include <iostream>
#include <map>
#include <set>
#include <vector>
#include <string>
#include <iterator>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "../mycryptolib/symmetric_key/key.h"
#include "../mycryptolib/hash/sha256.h"
#include <NTL/ZZ.h>

void user_1();
void user_2();

#define EXPONENTIAL

#ifdef EXPONENTIAL
static const std::string SHARED_PRIVATE_PASSWORD = "|bE8%au#u'ho2la@@uh4aj.mo";
#endif



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


std::vector<NTL::ZZ> findPrimefactors(NTL::ZZ n)
{
    std::set<NTL::ZZ> s;
    while (n % 2 == 0)
    {
        s.insert(NTL::conv<NTL::ZZ>(2));
        n = n / 2;
    }

    // n должно быть нечетным в этой точке. Так что мы можем пропустить
    // один элемент (примечание i = i +2)
    for (int i = 3; i <= NTL::SqrRoot(n); i += 2)
    {
        // Пока я делю n, выводим i и делим n
        while (n % i == 0)
        {
            s.insert(NTL::conv<NTL::ZZ>(i));
            n /= i;
        }
    }

    // Это условие для обработки случая, когда
    // n простое число больше 2
    if (n > 2)
    {
        s.insert(n);
    }

    return std::vector<NTL::ZZ>(s.begin(), s.end());
}

NTL::ZZ findPrimitive(NTL::ZZ n)
{
    NTL::ZZ phi = n - 1;

    // Находим простые факторы фи
    std::vector<NTL::ZZ> primitives = findPrimefactors(phi);

    for (NTL::ZZ i = NTL::conv<NTL::ZZ>(2); i < phi; i--)
    {
        // Перебираем все простые факторы фи.
        // и проверяем, нашли ли мы силу со значением 1

        bool flag = false;

        for (const NTL::ZZ &primitive : primitives)
        {
            // Проверка, если i ^ ((phi) / primefactors) mod n
            // равен 1 или нет

            if (NTL::PowerMod(i, phi / primitive, n) == NTL::conv<NTL::ZZ>(1))
            {
                flag = true;
                break;
            }
         }

         // Если не было мощности со значением 1.
         if (!flag)
         {
             return i;
         }
    }

    // Если примитивный элт не найден
    return NTL::conv<NTL::ZZ>(0);
}

void user_1()
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

    // generating dhparams
//    NTL::ZZ p = NTL::GenPrime_ZZ(2048, 100);
//    NTL::ZZ g = findPrimitive(p);

    NTL::ZZ p = NTL::conv<NTL::ZZ>("1090748135619415929450294929359784500348155124953172211774101106966150168922785639028532473848836817769712164169076432969224698752674677662739994265785437233596157045970922338040698100507861033047312331823982435279475700199860971612732540528796554502867919746776983759391475987142521315878719577519148811830879919426939958487087540965716419167467499326156226529675209172277001377591248147563782880558861083327174154014975134893125116015776318890295960698011614157721282527539468816519319333337503114777192360412281721018955834377615480468479252748867320362385355596601795122806756217713579819870634321561907813255153703950795271232652404894983869492174481652303803498881366210508647263668376514131031102336837488999775744046733651827239395353540348414872854639719294694323450186884189822544540647226987292160693184734654941906936646576130260972193280317171696418971553954161446191759093719524951116705577362073481319296041201283516154269044389257727700289684119460283480452306204130024913879981135908026983868205969318167819680850998649694416907952712904962404937775789698917207356355227455066183815847669135530549755439819480321732925869069136146085326382334628745456398071603058051634209386708703306545903199608523824513729625136659128221100967735450519952404248198262813831097374261650380017277916975324134846574681307337017380830353680623216336949471306191686438249305686413380231046096450953594089375540285037292470929395114028305547452584962074309438151825437902976012891749355198678420603722034900311364893046495761404333938686140037848030916292543273684533640032637639100774502371542479302473698388692892420946478947733800387782741417786484770190108867879778991633218628640533982619322466154883011452291890252336487236086654396093853898628805813177559162076363154436494477507871294119841637867701722166609831201845484078070518041336869808398454625586921201308185638888082699408686536045192649569198110353659943111802300636106509865023943661829436426563007917282050894429388841748885398290707743052973605359277515749619730823773215894755121761467887865327707115573804264519206349215850195195364813387526811742474131549802130246506341207020335797706780705406945275438806265978516209706795702579244075380490231741030862614968783306207869687868108423639971983209077624758080499988275591392787267627182442892809646874228263172435642368588260139161962836121481966092745325488641054238839295138992979335446110090325230955276870524611359124918392740353154294858383359");
#ifndef EXPONENTIAL
    NTL::ZZ g(17);
#else
    MyCryptoLib::SHA256 sha;
    sha.update(SHARED_PRIVATE_PASSWORD);
    NTL::ZZ g = NTL::ZZFromBytes(sha.digest().data(), 32);
#endif
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


    NTL::ZZ x = NTL::RandomBnd(p - 1);

    NTL::ZZ alpha = NTL::PowerMod(g, x, p);

    std::vector<uint8_t> buffer;
    buffer.resize(NTL::NumBytes(p)
                  +
              #ifndef EXPONENTIAL
                  NTL::NumBytes(g)
              #endif
                  +
                  NTL::NumBytes(alpha) + 24);

    size_t pos = 0;
    size_t intSize = NTL::NumBytes(p);
    buffer[pos++] = static_cast<uint8_t>(intSize >> 56);
    buffer[pos++] = static_cast<uint8_t>(intSize >> 48);
    buffer[pos++] = static_cast<uint8_t>(intSize >> 40);
    buffer[pos++] = static_cast<uint8_t>(intSize >> 32);
    buffer[pos++] = static_cast<uint8_t>(intSize >> 24);
    buffer[pos++] = static_cast<uint8_t>(intSize >> 16);
    buffer[pos++] = static_cast<uint8_t>(intSize >> 8);
    buffer[pos++] = static_cast<uint8_t>(intSize);
    NTL::BytesFromZZ(&buffer.data()[pos], p, NTL::NumBytes(p));
    pos += NTL::NumBytes(p);

#ifndef EXPONENTIAL
    intSize = NTL::NumBytes(g);
    buffer[pos++] = static_cast<uint8_t>(intSize >> 56);
    buffer[pos++] = static_cast<uint8_t>(intSize >> 48);
    buffer[pos++] = static_cast<uint8_t>(intSize >> 40);
    buffer[pos++] = static_cast<uint8_t>(intSize >> 32);
    buffer[pos++] = static_cast<uint8_t>(intSize >> 24);
    buffer[pos++] = static_cast<uint8_t>(intSize >> 16);
    buffer[pos++] = static_cast<uint8_t>(intSize >> 8);
    buffer[pos++] = static_cast<uint8_t>(intSize);
    NTL::BytesFromZZ(&buffer.data()[pos], g, NTL::NumBytes(g));
    pos += NTL::NumBytes(g);
#endif

    intSize = NTL::NumBytes(alpha);
    buffer[pos++] = static_cast<uint8_t>(intSize >> 56);
    buffer[pos++] = static_cast<uint8_t>(intSize >> 48);
    buffer[pos++] = static_cast<uint8_t>(intSize >> 40);
    buffer[pos++] = static_cast<uint8_t>(intSize >> 32);
    buffer[pos++] = static_cast<uint8_t>(intSize >> 24);
    buffer[pos++] = static_cast<uint8_t>(intSize >> 16);
    buffer[pos++] = static_cast<uint8_t>(intSize >> 8);
    buffer[pos++] = static_cast<uint8_t>(intSize);
    NTL::BytesFromZZ(&buffer.data()[pos], alpha, NTL::NumBytes(alpha));

    sendall(opSocket, buffer);
    recvall(opSocket, buffer);

    NTL::ZZ beta = NTL::ZZFromBytes(buffer.data(), buffer.size());
    NTL::ZZ keyInt = NTL::PowerMod(beta, x, p);

    std::vector<uint8_t> keyBytes(NTL::NumBytes(keyInt), 0x00);
    NTL::BytesFromZZ(keyBytes.data(), keyInt, keyBytes.size());

    MyCryptoLib::Key k(keyBytes);
    std::cout << k.rawString() << std::endl;

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

    std::vector<uint8_t> buffer;
    recvall(sockfd, buffer);

    size_t pos = 0;
    size_t intSize = static_cast<size_t>(buffer[pos]) << 56 |
                     static_cast<size_t>(buffer[pos + 1]) << 48 |
                     static_cast<size_t>(buffer[pos + 2]) << 40 |
                     static_cast<size_t>(buffer[pos + 3]) << 32 |
                     static_cast<size_t>(buffer[pos + 4]) << 24 |
                     static_cast<size_t>(buffer[pos + 5]) << 16 |
                     static_cast<size_t>(buffer[pos + 6]) << 8 |
                     static_cast<size_t>(buffer[pos + 7]);
    pos += 8;
    NTL::ZZ p = NTL::ZZFromBytes(&buffer.data()[pos], intSize);
    pos += intSize;

#ifndef EXPONENTIAL
    intSize = static_cast<size_t>(buffer[pos]) << 56 |
              static_cast<size_t>(buffer[pos + 1]) << 48 |
              static_cast<size_t>(buffer[pos + 2]) << 40 |
              static_cast<size_t>(buffer[pos + 3]) << 32 |
              static_cast<size_t>(buffer[pos + 4]) << 24 |
              static_cast<size_t>(buffer[pos + 5]) << 16 |
              static_cast<size_t>(buffer[pos + 6]) << 8 |
              static_cast<size_t>(buffer[pos + 7]);
    pos += 8;
    NTL::ZZ g = NTL::ZZFromBytes(&buffer.data()[pos], intSize);
    pos += intSize;
#else
    MyCryptoLib::SHA256 sha;
    sha.update(SHARED_PRIVATE_PASSWORD);
    NTL::ZZ g = NTL::ZZFromBytes(sha.digest().data(), 32);
#endif

    intSize = static_cast<size_t>(buffer[pos]) << 56 |
              static_cast<size_t>(buffer[pos + 1]) << 48 |
              static_cast<size_t>(buffer[pos + 2]) << 40 |
              static_cast<size_t>(buffer[pos + 3]) << 32 |
              static_cast<size_t>(buffer[pos + 4]) << 24 |
              static_cast<size_t>(buffer[pos + 5]) << 16 |
              static_cast<size_t>(buffer[pos + 6]) << 8 |
              static_cast<size_t>(buffer[pos + 7]);
    pos += 8;
    NTL::ZZ alpha = NTL::ZZFromBytes(&buffer.data()[pos], intSize);

    NTL::ZZ y = NTL::RandomBnd(p - 1);
    NTL::ZZ beta = NTL::PowerMod(g, y, p);

    buffer.resize(NTL::NumBytes(beta));
    NTL::BytesFromZZ(buffer.data(), beta, buffer.size());
    sendall(sockfd, buffer);

    NTL::ZZ keyInt = NTL::PowerMod(alpha, y, p);
    std::vector<uint8_t> keyBytes(NTL::NumBytes(keyInt), 0x00);
    NTL::BytesFromZZ(keyBytes.data(), keyInt, keyBytes.size());
    MyCryptoLib::Key k(keyBytes);

    std::cout << k.rawString() << std::endl;

    //#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

    close(sockfd);
}
