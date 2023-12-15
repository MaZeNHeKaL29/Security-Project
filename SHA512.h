#pragma once

#pragma warning(disable : 4996)

#include <iostream>
#include <fstream>
#include <cstring>
#include <string>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

namespace hashSHA512
{
	std::string computeSHA512(const unsigned char* data, size_t size);

}

