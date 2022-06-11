#include <iostream>
#include <algorithm>

#include "../mycryptolib/hash/sha256.h"
#include "../mycryptolib/symmetric_key/key.h"
#include "../mycryptolib/hash/hmac.h"

int main(int argc, char **argv)
{
    // Я устал парсить аргументы и мне лень их перемещать в отдельный хедер

    MyCryptoLib::Key k = MyCryptoLib::Key::generate(256);
    std::cout << k.b64() << std::endl;

    MyCryptoLib::SHA256 sha;
    // here setup hsah
    // eg
    // MyCryptoLib::Streebog streebog;
    // streebog.setMode(256);
    // MyCryptoLib::HMAC hmac(&streebog);

    MyCryptoLib::HMAC hmac(&sha); // Стоит заметить что здесь используется ммм не умный (или как их там =) ) указатель и это имеет значение, если мы хотим высвободить sha после этой строки, ну ты знаешь
    hmac.create("Here Some STD::STRING or STD::VECTOR<UINT8_T> AS BYTES U KNOW", k);
    std::cout << hmac.hex() << std::endl;
}

