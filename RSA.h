#pragma once

#include <iostream>
#include <fstream>
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

namespace RSACrypto
{
	enum class KEY : uint8_t
	{
		PUBLIC_KEY,
		PRIVATE_KEY
	};

	void generateRSA_keys(const char* public_key_filename, const char* private_key_filename);

	std::string RSAEncryptData(const std::string& inputData, const std::string& outputFile, const std::string& keyFile, KEY keyType);

	std::string RSAEncryptData(const std::string& inputData, const std::string& outputFile, RSA* key, KEY keyType);

	std::string RSAEncryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& keyFile, KEY keyType);

	std::string RSAEncryptFile(const std::string& inputFile, const std::string& outputFile, RSA* key, KEY keyType);

	std::string RSADecryptData(const std::string& inputData, const std::string& outputFile, const std::string& keyFile, KEY keyType);

	std::string RSADecryptData(const std::string& inputData, const std::string& outputFile, RSA* key, KEY keyType);

	std::string RSADecryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& keyFile, KEY keyType);

	std::string RSADecryptFile(const std::string& inputFile, const std::string& outputFile, RSA* key, KEY keyType);

	std::string RSAEncryptAndHashFile(const std::string& inputFile, const std::string& outputFile, const std::string& hashFile, const std::string& keyFile, KEY keyType);

	std::string RSAEncryptAndHashFile(const std::string& inputFile, const std::string& outputFile, const std::string& hashFile, RSA* key, KEY keyType);

	std::string RSAEncryptAndHashData(const std::string& inputData, const std::string& outputFile, const std::string& hashFile, const std::string& keyFile, KEY keyType);

	std::string RSAEncryptAndHashData(const std::string& inputData, const std::string& outputFile, const std::string& hashFile, RSA* key, KEY keyType);

	std::string RSADecryptAndHashFile(const std::string& inputFile, const std::string& outputFile, const std::string& hashEncryptedFile, const std::string& hashDecryptedFile, const std::string& keyFile, KEY keyType);

	std::string RSADecryptAndHashFile(const std::string& inputFile, const std::string& outputFile, const std::string& hashEncryptedFile, const std::string& hashDecryptedFile, RSA* key, KEY keyType);

	std::string RSADecryptAndHashData(const std::string& inputData, const std::string& outputFile, const std::string& hashEncryptedFile, const std::string& hashDecryptedFile, const std::string& keyFile, KEY keyType);

	std::string RSADecryptAndHashData(const std::string& inputData, const std::string& outputFile, const std::string& hashEncryptedFile, const std::string& hashDecryptedFile, RSA* key, KEY keyType);


	void RSASignFile(const std::string& inputFile, const std::string& outputFile, RSA* key);

	void RSASignFile(const std::string& inputFile, const std::string& outputFile, const std::string& keyFile);

	void RSASignData(const std::string& inputData, const std::string& outputFile, RSA* key);

	void RSASignData(const std::string& inputData, const std::string& outputFile, const std::string& keyFile);



	bool RSAVerifyFile(const std::string& inputFile, const std::string& outputFile, RSA* key);

	bool RSAVerifyFile(const std::string& inputFile, const std::string& outputFile, const std::string& keyFile);

	bool RSAVerifyData(const std::string& inputData, const std::string& outputFile, RSA* key);

	bool RSAVerifyData(const std::string& inputData, const std::string& outputFile, const std::string& keyFile);

}

