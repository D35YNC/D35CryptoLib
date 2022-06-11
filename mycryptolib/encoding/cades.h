#ifndef CAdES_H
#define CAdES_H

#include <map>
#include <vector>
#include <string>
#include <sstream>
#include <fstream>

#include "base64.h"
#include "../hash/sha256.h"
#include "../hash/sha512.h"
#include "../hash/streebog.h"
#include "../exceptions.h"

namespace MyCryptoLib
{
class CAdES
{
public:
    static CAdES create(uint8_t version, const std::string &contentType, const std::string &signerId, const std::vector<uint8_t> &signerPubKeyHash,
                        const std::string &hashingAlgorithmId, const std::string &signingAlgorithmId, const std::vector<uint8_t> &originalHash,
                        const std::vector<uint8_t> &signature);
    static CAdES fromFileBytes(std::vector<uint8_t> &buffer);
    static CAdES fromBytes(const std::vector<uint8_t> &buffer);
    static CAdES fromFile(const std::string &filename);

    void appendCASign(uint64_t time, const std::vector<uint8_t> &pubKeyHash, const std::vector<uint8_t> &signature);

    // Get sign info
    uint8_t getVersion() const;
    std::string getContentType() const;
    std::vector<uint8_t> getContentHash() const;
    std::string getSignerName() const;
    std::vector<uint8_t> getSignerKeyFingerprint() const;
    std::string getHashAlgorithmId() const;
    std::string getSignAlgorithmId() const;
    std::vector<uint8_t> getSignature() const;

    // Get CA sign info
    bool isSignedByCA() const;
    uint64_t getCATimestamp() const;
    std::vector<uint8_t> getCAKeyFingerprint() const;
    std::vector<uint8_t> getCASignature() const;

    // Savin
    std::vector<uint8_t> toBytes(bool includeHeaders = true) const;
    std::vector<uint8_t> toPem() const;

    friend std::ostream& operator<<(std::ostream &out, const CAdES &cadesSign)
    {
        std::vector<uint8_t> buf = cadesSign.getSignature();
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (std::vector<uint8_t>::const_iterator it = buf.begin(); it != buf.end(); it++) {
            ss << std::setw(2) << static_cast<unsigned>(*it);
        }
        std::string sign = ss.str();

        ss.str(std::string());
        buf = cadesSign.getContentHash();
        ss << std::hex << std::setfill('0');
        for (std::vector<uint8_t>::const_iterator it = buf.begin(); it != buf.end(); it++) {
            ss << std::setw(2) << static_cast<unsigned>(*it);
        }
        std::string contentHash = ss.str();

        ss.str(std::string());
        buf = cadesSign.getSignerKeyFingerprint();
        ss << std::hex << std::setfill('0');
        for (std::vector<uint8_t>::const_iterator it = buf.begin(); it != buf.end(); it++) {
            ss << std::setw(2) << static_cast<unsigned>(*it);
        }
        std::string pubkeyFingerprint = ss.str();

        out << "CMS Version:  " << static_cast<int>(cadesSign.getVersion()) << std::endl <<
               "Content type: " << cadesSign.getContentType()       << std::endl <<
               "Content hash: " << contentHash                      << std::endl <<
               "Signer:       " << cadesSign.getSignerName()        << std::endl <<
               "Pubkey fingerprint: " << pubkeyFingerprint          << std::endl <<
               "Hash algo:    " << cadesSign.getHashAlgorithmId()   << std::endl <<
               "Sign algo:    " << cadesSign.getSignAlgorithmId()   << std::endl <<
               "Signature:    " << sign;

        if (cadesSign.isSignedByCA())
        {
            ss.str(std::string());
            buf = cadesSign.getCAKeyFingerprint();
            ss << std::hex << std::setfill('0');
            for (std::vector<uint8_t>::const_iterator it = buf.begin(); it != buf.end(); it++) {
                ss << std::setw(2) << static_cast<unsigned>(*it);
            }
            std::string caKeyFingerprint = ss.str();

            ss.str(std::string());
            buf = cadesSign.getCASignature();
            ss << std::hex << std::setfill('0');
            for (std::vector<uint8_t>::const_iterator it = buf.begin(); it != buf.end(); it++) {
                ss << std::setw(2) << static_cast<unsigned>(*it);
            }
            std::string caSignature = ss.str();

            out << std::endl <<
                   "CA Timestamp: " << cadesSign.getCATimestamp() << std::endl <<
                   "CA PubKey Fingerprint: " << caKeyFingerprint << std::endl <<
                   "CA Signature: " << caSignature;
        }


        return out;
    }

protected:
    CAdES() {}
    CAdES(const std::map<int, std::vector<uint8_t>> &signData);
    void setCASignData(const std::map<int, std::vector<uint8_t>> &caSign);

    std::map<int, std::vector<uint8_t>> signData;
    std::map<int, std::vector<uint8_t>> caSignData;

    std::string pemHeader = "-----BEGIN CADES SIGNATURE-----";
    std::string pemTerminator = "-----END CADES SIGNATURE-----";
};

}

#endif // CAdES_H
