#include "SHA512.h"


namespace hashSHA512
{
    // Function to compute SHA-256 hash of a given data
    std::string computeSHA512(const unsigned char* data, size_t size)
    {
        unsigned char hash[SHA512_DIGEST_LENGTH];
        SHA512(data, size, hash);

        std::string result(reinterpret_cast<char*>(hash), SHA512_DIGEST_LENGTH);
        return result;
    }
}