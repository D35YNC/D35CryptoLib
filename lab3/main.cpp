#include <iostream>
#include <algorithm>
#include <iomanip>

#include "../mycryptolib/public_key/rsa.h"
#include "../mycryptolib/public_key/rsakey.h"
#include "../mycryptolib/encoding/pkcs7.h"
#include "../mycryptolib/encoding/pkcs8.h"
#include "../mycryptolib/encoding/pkcs12.h"

void usage()
{
    std::cout << "./lab3 {keygen, encrypt, decrypt} {--infile [FILENAME], --outfile [FILENAME] --keyfile [FILENAME]} {keysize}" << std::endl;
    exit(0);
}


int main(int argc, char **argv)
{
    // Arguments parsing
    const std::vector<std::string> avArgs = {"keygen", "encrypt", "decrypt", "--infile", "--outfile", "--keyfile"};
    std::vector<std::string> args;
    if (argc > 1)
    {
        args.assign(argv + 1, argv + argc);
    }
    else
    {
        usage();
    }

    int workMode = -1; // keygen = 0/encrypt = 1/decrypt = 2
    int keySize  = -1; // Only for keygen
    std::string outputFilename = "";
    std::string inputFilename  = "";
    std::string keyFilename    = "";
    bool nextIsParam = false;  // При трю - следующий args[i + 1] фактически не парсится тк уже был распраршен когда было установлено трю

    // Заранее обработаем режим работы
    auto iter_ = std::find(avArgs.begin(), avArgs.end(), args[0]);
    if (iter_ != avArgs.end())
    {
        // Индекс аргумента в avArgs
        workMode = iter_ - avArgs.begin();
    }
    else
    {
        std::cerr << "[ERROR] Unknown work mode" << std::endl;
        usage();
    }


    for (int i = 1; i < args.size(); i++)
    {
        if (nextIsParam)
        {
            nextIsParam = false;
            continue;
        }

        // Ищем iй аргумент внутри avArgs
        auto iter_ = std::find(avArgs.begin(), avArgs.end(), args[i]); // Да кто такой ваш итератор
        if (args[i].rfind("--", 0) == 0 && iter_ != avArgs.end())
        {
            // Индекс аргумента в avArgs
            int index = iter_ - avArgs.begin();
            // index = *iter_;

            if (i + 1 >= args.size()) // Все аргументы с --XXX имеют параметры поэтому можно проверить сразу же наличие параметра для текущего аргумента
            {
                usage(); // Тут выход при отсутствии параметра//хелп бы написать еще
            }

            switch (index)
            {
            case 3:
            {
                inputFilename = args[i + 1];
                nextIsParam = true;
                continue;
            }
            case 4:
            {
                outputFilename = args[i + 1];
                nextIsParam = true;
                continue;
            }
            case 5:
            {
                keyFilename = args[i + 1];
                nextIsParam = true;
                continue;
            }
            default:
            {
                std::cerr << "[ERROR] H-N ERROR " << std::endl;
                exit(-1);
                break;
            }
            }

        }
        else
        {
            if (workMode != 0)
            {
                std::cerr << "Unknown argument: " << args[i] << std::endl;
                usage();
            }
            else
            {
                try
                {
                    keySize = std::stoi(args[i]);
                }
                catch (std::invalid_argument& ex)
                {
                    std::cerr << "Key size must be int" << std::endl;
                    usage();
                }
            }
//            if (keySize % 2048 != 0 || keySize <= 0)
//            {
//                std::cerr << "Key size must be a positive multiple of 2048" << std::endl;
//                usage();
//            }
        }
    }

    // Извините
    if ((workMode > 0 && (outputFilename.empty() || inputFilename.empty() || keyFilename.empty())))
    {
        usage();
    }
    else if (workMode == 0 && (keyFilename.empty() || keySize % 2048 != 0 || 0 >= keySize))
    {
        std::cerr << "Key size must be a positive multiple of 2048" << std::endl;
        usage();
    }

    switch (workMode)
    {
        case 0:
        {
            MyCryptoLib::RSAKey key = MyCryptoLib::RSAKey::generate(keySize);

            std::ofstream keyFile(keyFilename + ".pub");
            if (!keyFile.is_open())
            {
                std::cout << "[ERROR] cant open file " << keyFilename << std::endl;
                exit(-1);
            }

            std::vector<uint8_t> buffer = key.exportPublicKeyBytes();

            keyFile.write((char*)buffer.data(), buffer.size());
            keyFile.flush();
            keyFile.close();
            ///
            keyFile.open(keyFilename);
            if (!keyFile.is_open())
            {
                std::cout << "[ERROR] cant open file " << keyFilename << std::endl;
                exit(-1);
            }

            buffer = key.exportPrivateKeyBytes();
            keyFile.write((char*)buffer.data(), buffer.size());
            keyFile.flush();
            keyFile.close();

            break;
        }
        case 1:
        {
            MyCryptoLib::RSA rsaCipher;
            MyCryptoLib::RSAKey key = MyCryptoLib::RSAKey::fromPKCS8File(keyFilename);

            std::ifstream inputFile(inputFilename);
            if (!inputFile.is_open())
            {
                std::cerr << "[ERROR] Cant open " << inputFilename << std::endl;
                exit(-1);
            }

            inputFile.seekg(0, std::ios::end);
            size_t size = inputFile.tellg();
            inputFile.seekg(0, std::ios::beg);
            std::vector<uint8_t> buffer(size, 0x00);

            // А как насчет читать файл по блокам == размер ключа для ускорения ????
            inputFile.read((char*)buffer.data(), size); // Звучит логично и правильно так то
            inputFile.close();

            std::ofstream outputFile(outputFilename + ".p7s");
            if (!outputFile.is_open())
            {
                std::cerr << "[ERROR] Cant open " << inputFilename << std::endl;
                exit(-1);
            }

            buffer = rsaCipher.encrypt("data", buffer, key)
                              .toBytes();
            outputFile.write((char*)buffer.data(), buffer.size());
            outputFile.flush();
            outputFile.close();
            break;
        }
        case 2:
        {
            MyCryptoLib::RSA rsaCipher;
            MyCryptoLib::RSAKey key = MyCryptoLib::RSAKey::fromPKCS12File(keyFilename);

            MyCryptoLib::PKCS7 pkcs7 = MyCryptoLib::PKCS7(inputFilename);
            std::vector<uint8_t> outputBuffer = rsaCipher.decrypt(pkcs7.getData(), key);

            std::ofstream outputFile(outputFilename);
            if (!outputFile.is_open())
            {
                std::cout << "[ERROR] Cant open " << inputFilename << std::endl;
                exit(-1);
            }

            outputFile.write((char*)outputBuffer.data(), outputBuffer.size());
            outputFile.flush();
            outputFile.close();
            break;
        }
        default:
        {
            std::cout << "[ERROR] unknwn ERROR" << std::endl;
            usage();
            break;
        }
    }


//    MyCryptoLib::RSAKey k = MyCryptoLib::RSAKey::generate(4096);
//    std::cout << k.exportPrivateKey().toPem() << std::endl << k.exportPublicKey().toPem() << std::endl;
//    MyCryptoLib::RSAKey k(/*n*/NTL::conv<NTL::ZZ>("1004697572938601717732690313563380711760965942609492269519672345017721800209182537854223878066001794811077926402693229712003901402517019353710226971624239539630044816834826201442830503181459937273731128964972624342046824299892547277831155577629229696586563721999414920861287159221386479137848017838641818875713011185853202259671811408048685557897012378067377468868324548725385242579050945206876518279459947095745622051270593463939390815264357131048903565150665789593781482945562234386772509923965561076428717836845810089859437111020578703914437536000746210762938791333250183228955268356627143127662781736027976743284700810320299004233233506210788958337669532915115386274890023091995504520804220716418799405302986459357091067700434323074370905268171020114295461197369379442375245191977340639263297177180219420116632120248984240857684595811966622511252502420398523037407149554180670454485484645026017480539726904973644179608831520675565727081125504933498940713014370376616989219458854249520939888012796570756640617637238151985786299980617922515296573688812646017760225003578250609343960898398132581017118640374210656055281721354884468947786841436817287109661186362467680861295648116540947618914095618846837478325374745532952423272378603"),
//                          /*e*/NTL::conv<NTL::ZZ>(65537),
//                          /*p*/NTL::conv<NTL::ZZ>("32119472035446544164104327521359373647088743383573450097798088907102941962067049427450119387609776981353401076388513289844922263721471732353761134688770825996346169398602304962055530895463843858938139990723751631064122383656978570781967790625877519247609795198522725874616591104715851430377997652335008497107904853284480142718767877176375705068315875204575015285596437494309556423292567326776897945998809067840722881220201133680120895169943642429642591940160193522804493124586945380095894864117544615616406103638665083570939599646241415150245619775691202532556738926271092027981417352486541418937674995768933455911271"),
//                          /*q*/NTL::conv<NTL::ZZ>("31280015182996572238010276364941725201299072410977768716983676926294967793009130532653922752224687699711162762023929536478471076696606953258315032027589075795820409934140306197870183445150374678081586641748658280283294480919713940810921686373187559637985828038947527462438711237981843094552118423615445288839728448062484790197039611959577900989171169611882235714310456011127058925018533266796316403475661324642724359988951274778244079067493586730815559036072822703785318492732477619666942599894102506788621624351911166251229536422981684478181511457970079053325276113608571208877192275040974294157869898550967840982493"),
//                          /*d*/NTL::conv<NTL::ZZ>("44503670510410314579214794395143113145888339890372706385943952539579876802527685237206645376285200884028246949769114330133318976631626519123865738416851051826388453900415039791088041117777411201392213061100073675404152325290874845469640731828702165329368059034809367460523316954082197063295127878688026613915725032768235441961445725583492289463585866510972378841337659107829063875474692066093390490337858406990700532750027203347972161324327154911499871059590502879148384042464061010189672952824694810639372688410567872970412834479648747691588143598427853729111972034734963179786336634867152852581061925014712551471005728117680590642265613772904441978795150590099155960263460725542038779496706693765958048724577417955422203346376085544960586037295982253802704834581773894537630303683526375567756951899283975467073787000758866674355201344038832518867385696243169910944780369280377652073391982876995854842317394421014158201685031738519570113313895229885190832224481320661869543989446025520133756512275528630901394200899918636272001792918559891666559651775513543697531519189216123301642251932873042673976286614405720782644018517766650449397919399561646548073990265777688311028845552781750770943604666642715669338899347230632317794449433"));
//    std::cout << k.exportPrivateKey() << std::endl;

//    std::ifstream key("/home/d35ync/test.pem");
//    MyCryptoLib::RSAKey k(key);
//    std::cout<<k.size()<<std::endl;

    return 0;
}
