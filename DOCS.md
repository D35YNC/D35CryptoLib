# Всем привет это документация
извините  


### Cтруктура
<details><summary>~$ tree ./cryptolib</summary>

```bash
├── encoding
│   ├── base32.h
│   └── base64.h
├── hash
│   ├── crc32.h
│   ├── hash_base.h
│   ├── hmac.h
│   ├── sha256.cpp
│   ├── sha256.h
│   ├── sha512.cpp
│   ├── sha512.h
│   ├── streebog.cpp
│   └── streebog.h
├── public_key
│   ├── elgamal.h
│   ├── elgamalkey.cpp
│   ├── elgamalkey.h
│   ├── fiatshamir.h
│   ├── fiatshamirkey.cpp
│   ├── fiatshamirkey.h
│   ├── rsa.cpp
│   ├── rsa.h
│   ├── rsakey.cpp
│   └── rsakey.h
├── symmetric_key
│   ├── key.h
│   ├── rc4.h
│   └── symmetric_cipher_base.h
├── exceptions.h
└── utils.h
```

</details>

### Содержание
 - [Encoding](#encoding)  
    - Base64
    - Base32
- [Hash](#hash)
    - SHA256
    - SHA512
    - Streebog (GOST 34.11-2012)
    - HMAC
- [Public Key](#pubkey)
    - RSA (Ciper + sign)
        - RSAKey
    - ElGamal (Sign)
        - ElGamalKey
    - FiatShamir (Sign)
        - FiatShamirKey
- [Symmetric Key](#symkey)
    - Key
    - RC4
- [other](#oth)
    - Exceptions
    - Utils


<a name="encoding"><h3>Encoding</h3></a>

#### `D35Crypto::Base64`
Encode:  
 - `static std::string encode(const std::string &data);`
 - `static std::string encode(const std::vector<uint8_t> &data);`


Decode:  
 - `static std::vector<uint8_t> decode(const std::string &data);`


#### `D35Crypto::Base32`

Encode:  
 - `static std::string encode(const std::string &data);`
 - `static std::string encode(const std::vector<uint8_t> &data);`


Decode:  
 - `static std::vector<uint8_t> decode(const std::string &data);`

Some usage:
https://github.com/D35YNC/D35CryptoLib/blob/0aefd556fe0dc89fbfec8d8f2173f472a0098cef/examples/base32-64/main.cpp#L14-L26

<a name="hash"><h3>Hash</h3></a>

#### `D35Crypto::HashBase`
*This paragraph needs rework*  
Basic abstract class for all hash functions.  
Requires redefinition of methods:  
 - `virtual void update(const std::string &data) = 0;`
 - `virtual void update(const std::vector<uint8_t> &data) = 0;`
 - `virtual void update(std::ifstream& file) = 0;`
 - `virtual size_t blockSize() = 0;`
// Add descriptions  

It also provides the results of the functions:
 - `std::vector<uint8_t> digest()` - Returns raw-bytes digest
 - `std::string hexDigest()` - Returns hex-encoded digest
  
For normal operation of all methods, it is necessary to put the digest in `D35Crypto::HashBase::_digest` (`this->_digest`):  
Definition:
```cpp
protected:
    std::vector<uint8_t> _digest;
```
Usage:  
```cpp
void update(const std::vector<uint8_t> &data)
{
    std::vector<uint8_t> digest;
    /* Calculating */
    this->_digest = digest;
}
```

#### `D35Crypto::SHA256: public HashBase`

Calculating digest according to `D35Crypto::HashBase`  
Output of the result according to `D35Crypto::HashBase`


#### `D35Crypto::SHA512: public HashBase`

Calculating digest according to `D35Crypto::HashBase`  
Output of the result according to `D35Crypto::HashBase`


#### `D35Crypto::Streebog: public HashBase`

Calculating digest according to `D35Crypto::HashBase`  
Output of the result according to `D35Crypto::HashBase`  

Setup digest size:  
Always initialized with digest size = 64 bytes (512 bits). For change 'work mode' u need use `void setMode(int digestSize);`. That method manually set required digest size. **Takes values 256 and 512**.

#### `D35Crypto::HMAC<HashBase>`
Init:  
`D35Crypto::HMAC<D35Crypto::SHA256> hmac;`

Calculating:
 - `void create(const std::string&, const Key&);`
 - `void create(const std::vector<uint8_t>&, const Key&);`

Output:  
 - `std::vector<uint8_t> raw();` - raw-bytes hmac
 - `std::string hex();` - hex-encoded hmac

Some usages:
https://github.com/D35YNC/D35CryptoLib/blob/aff9435339139d9fbed014ffb294e553c82e2f2e/examples/sha/main.cpp#L33-L35

https://github.com/D35YNC/D35CryptoLib/blob/aff9435339139d9fbed014ffb294e553c82e2f2e/examples/hmac/main.cpp#L9-L14

<a name="pubkey"><h3>Public key</h3></a>

#### `MyCryptoLib::RSA`
// TODO  

#### `MyCryptoLib::ElGamal`
// TODO  

#### `MyCryptoLib::RSAKey`
// TODO  

#### `MyCryptoLib::ElGamalKey`
// TODO  

<a name="symkey"><h3>Symmetric key</h3></a>

#### `MyCryptoLib::Key`
По факту это обертка над вектором байт :trollface:  
// TODO  
