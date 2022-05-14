# Всем привет это документация
извините  

### Cтруктура
<details><summary>~$ tree ./cryptolib</summary>

```bash
├── encoding
│   ├── base32.h
│   ├── base64.h
│   ├── ipkcs.h
│   ├── pkcs12.cpp
│   ├── pkcs12.h
│   ├── pkcs7.cpp
│   ├── pkcs7.h
│   ├── pkcs8.cpp
│   └── pkcs8.h
├── exceptions.h
├── hash
│   ├── hmac.cpp
│   ├── hmac.h
│   ├── ihash.h
│   ├── sha256.cpp
│   ├── sha256.h
│   ├── sha512.cpp
│   ├── sha512.h
│   ├── streebog.cpp
│   └── streebog.h
├── public_key
│   ├── elgamal.cpp
│   ├── elgamal.h
│   ├── elgamalkey.cpp
│   ├── elgamalkey.h
│   ├── rsa.cpp
│   ├── rsa.h
│   ├── rsakey.cpp
│   └── rsakey.h
└── symmetric_key
    └── key.h
```

</details>

### Классы

#### `MyCryptoLib::Base64`
Кодирование:  
 - `static std::string b64Encode(const std::vector<uint8_t> &data);`
 - [Дописать перегрузку]
Декодирование:  
 - `static std::vector<uint8_t> b64Decode(const std::string &data);`
Для `MyCryptoLib::Base64` - методы аналогичны, но с префиксом `b32` вместо `b64`.  


#### `MyCryptoLib::PKCS7`
#### `MyCryptoLib::PKCS8/12`
,kznm  
здесь все ясно  

#### `MyCryptoLib::SHA256/512`
BASED ON `IHash` Abstract Class  
Вычисление дайджеста:  
 - `void update(const std::vector<uint8_t>&) override;` + 2 overloads - Update digest
 - `OvErLoAd`
Вывод:  
 - `std::string hexDigest();` (from IHash) - gets digest
 - `mOr3`

#### `MyCryptoLib::Streebog`
BASED ON `IHash` Abstract Class  
`void setMode(int digestSize);` - Устанавливает размер дайджеста  
Остальное аналогично SHA(т.е согласно интерфейсу)  

#### `MyCryptoLib::HMAC`
Конструктор:  
 - `HMAC(IHash *hashAlgorythm);` - HMAC init
Вычисление HMAC:
 - `void create(const std::vector<uint8_t>&, const Key&);` + 1 overload - create HMAC
Вывод:  
 - `std::string hex();` - HMAC output
 - MoR3
 
#### `MyCryptoLib::RSA`
InPrOgReSs  

#### `MyCryptoLib::ElGamal`
InPrOgReSs  

#### `MyCryptoLib::RSAKey`
InPrOgReSs  

#### `MyCryptoLib::ElGamalKey`
InPrOgReSs  

#### `MyCryptoLib::Key`
По факту это обертка над вектором байт :trollface:  
InPrOgReSs  
