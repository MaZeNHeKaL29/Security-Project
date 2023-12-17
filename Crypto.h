#pragma once

#include <string>
#include <iostream>
#include <fstream>
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "AES.h"
#include "RSA.h"
#include "SHA512.h"

#define RSA_LENGTH 256


namespace Crypto
{

	class CryptoClient
	{
	public:

		explicit CryptoClient(std::string name) noexcept;

		~CryptoClient();

		// Getters
		std::string getName() const;
		std::string getPublicKeyPath() const;
		//std::string getPrivateKeyPath() const;
		std::string getAESEncryptedFile() const;
		std::string getAESDecryptedFile() const;
		std::string getRSAEncryptedFile() const;
		std::string getRSADecryptedFile() const;
		std::string getAESHashEncryptedFile() const;
		std::string getAESHashDecryptedFile() const;
		std::string getRSAHashEncryptedFile() const;
		std::string getRSAHashDecryptedFile() const;
		std::string getRSASignature() const;
		std::string getRSAVerification() const;
		std::string getEncrypted_SignedFile() const;
		std::string getDecrypted_VerifiedFile() const;
		RSA* getPublicKey() const;

		std::pair<std::string, bool> AESEncryptData(const std::string& inputData);

		std::pair<std::string, bool> AESEncryptFile(const std::string& inputFile);

		std::pair<std::string, bool> AESDecryptData(const std::string& inputData);

		std::pair<std::string, bool> AESDecryptFile(const std::string& inputFile);

		std::pair<std::string, bool> AESEncryptAndHashFile(const std::string& inputFile);

		std::pair<std::string, bool> AESEncryptAndHashData(const std::string& inputData);

		std::pair<std::string, bool> AESDecryptAndHashFile(const std::string& inputFile, const std::string& hashFile);

		std::pair<std::string, bool> AESDecryptAndHashData(const std::string& inputData, const std::string& hashFile);

		std::string RSAEncryptData(const std::string& inputData, RSA* key, RSACrypto::KEY keyType);

		std::string RSAEncryptData(const std::string& inputData, const std::string& keyPath, RSACrypto::KEY keyType);

		std::string RSAEncryptFile(const std::string& inputFile, RSA* key, RSACrypto::KEY keyType);

		std::string RSAEncryptFile(const std::string& inputFile, const std::string& keyPath, RSACrypto::KEY keyType);

		std::string RSADecryptData(const std::string& inputData, RSA* key, RSACrypto::KEY keyType);

		std::string RSADecryptData(const std::string& inputData, const std::string& keyPath, RSACrypto::KEY keyType);

		std::string RSADecryptFile(const std::string& inputFile, RSA* key, RSACrypto::KEY keyType);

		std::string RSADecryptFile(const std::string& inputFile, const std::string& keyPath, RSACrypto::KEY keyType);

		std::string RSAEncryptAndHashFile(const std::string& inputFile, RSA* key, RSACrypto::KEY keyType);

		std::string RSAEncryptAndHashFile(const std::string& inputFile, const std::string& keyPath, RSACrypto::KEY keyType);

		std::string RSAEncryptAndHashData(const std::string& inputData, RSA* key, RSACrypto::KEY keyType);

		std::string RSAEncryptAndHashData(const std::string& inputData, const std::string& keyPath, RSACrypto::KEY keyType);






		std::string RSADecryptAndHashFile(const std::string& inputFile, const std::string&hashFile, RSA* key, RSACrypto::KEY keyType);

		std::string RSADecryptAndHashFile(const std::string& inputFile, const std::string& hashFile, const std::string& keyPath, RSACrypto::KEY keyType);

		std::string RSADecryptAndHashData(const std::string& inputData, const std::string& hashFile, RSA* key, RSACrypto::KEY keyType);

		std::string RSADecryptAndHashData(const std::string& inputData, const std::string& hashFile, const std::string& keyPath, RSACrypto::KEY keyType);



		void RSASignFile(const std::string& inputFile);

		void RSASignData(const std::string& inputData);



		bool RSAVerifyFile(const std::string& inputFile, RSA* key);

		bool RSAVerifyFile(const std::string& inputFile, const std::string& keyFile);

		bool RSAVerifyData(const std::string& inputData, RSA* key);

		bool RSAVerifyData(const std::string& inputData, const std::string& keyFile);

		std::pair<std::string, bool> SignAndEncryptFile(const std::string& inputFile);

		std::pair<std::string, bool> SignAndEncryptData(const std::string& inputData);

		std::pair<std::string, bool> DecryptAndVerifyFile(const std::string& inputFile, const std::string& keyFile);

		std::pair<std::string, bool> DecryptAndVerifyData(const std::string& inputData, const std::string& keyFile);

		void generateAESKey();

		void generateRSAKeys();

	private:
		std::string name;
		RSA* publicKey;
		RSA* privateKey;
		std::string publicKeyPath;
		std::string privateKeyPath;
		unsigned char* AESKey;
		std::string AESEncryptedFile;
		std::string AESDecryptedFile;
		std::string RSAEncryptedFile;
		std::string RSADecryptedFile;
		std::string AESHashEncryptedFile;
		std::string AESHashDecryptedFile;
		std::string RSAHashEncryptedFile;
		std::string RSAHashDecryptedFile;
		std::string RSASignature;
		std::string RSAVerification;
		std::string Encrypted_SignedFile;
		std::string Decrypted_SignedFile;
		std::string Decrypted_VerifiedFile;
	};
}

