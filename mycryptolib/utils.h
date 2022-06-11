#pragma once

#include <string>

#include "hash/hash_base.h"
#include "hash/sha256.h"
#include "hash/sha512.h"
#include "hash/streebog.h"

namespace MyCryptoLib
{
    
    static HashBase* hashIdToHashPtr(const std::string &hashId)
    {
        HashBase* hash = nullptr;

        if (hashId == "SHA256")
        {
            hash = new MyCryptoLib::SHA256();
        }
        else if (hashId == "SHA512")
        {
            hash = new MyCryptoLib::SHA512();
        }
        else if (hashId == "Streebog256")
        {
            MyCryptoLib::Streebog *s;
            s = new MyCryptoLib::Streebog();
            s->setMode(256);
            hash = reinterpret_cast<HashBase*>(s);
        }
        else if (hashId == "Streebog512")
        {
            MyCryptoLib::Streebog *s;
            s = new MyCryptoLib::Streebog();
            s->setMode(512);
            hash = reinterpret_cast<HashBase*>(s);
        }

        return hash;
    }
    
    
    
    
}
