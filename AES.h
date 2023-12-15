#pragma once

#pragma warning(disable : 4996)

#include <iostream>
#include <fstream>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <random>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>


namespace AES
{
	std::pair<std::string, bool> AESEncryptData(const std::string& inputData, const std::string& outputFile, const unsigned char* key);

	std::pair<std::string, bool> AESEncryptFile(const std::string& inputFile, const std::string& outputFile, const unsigned char* key);

	std::pair<std::string, bool> AESDecryptData(const std::string& inputData, const std::string& outputFile, const unsigned char* key);

	std::pair<std::string, bool> AESDecryptFile(const std::string& inputFile, const std::string& outputFile, const unsigned char* key);

	std::pair<std::string, bool> AESEncryptAndHashFile(const std::string& inputFile, const std::string& outputFile, const std::string& hashFile, const unsigned char* key);

	std::pair<std::string, bool> AESEncryptAndHashData(const std::string& inputData, const std::string& outputFile, const std::string& hashFile, const unsigned char* key);

	std::pair<std::string, bool> AESDecryptAndHashFile(const std::string& inputFile, const std::string& outputFile, const std::string& hashEncryptedFile, const std::string& hashDecryptedFile, const unsigned char* key);

	std::pair<std::string, bool> AESDecryptAndHashData(const std::string& inputData, const std::string& outputFile, const std::string& hashEncryptedFile, const std::string& hashDecryptedFile, const unsigned char* key);

	class AESKey
	{
	public:
		AESKey() noexcept = delete;

		static void generateKey() noexcept
		{
			std::random_device rd;
			std::mt19937 gen(rd());
			std::uniform_int_distribution<> dis(0, 255);

			for (int i = 0; i < sizeof(key); ++i) {
				key[i] = static_cast<unsigned char>(dis(gen));
			}
		}

		static const unsigned char* getKey() noexcept
		{
			return key;
		}

	private:
		static unsigned char key[32];
	};
}

