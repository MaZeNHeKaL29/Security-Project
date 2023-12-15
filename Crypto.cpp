#include "Crypto.h"


namespace Crypto
{
	CryptoClient::CryptoClient(std::string name) noexcept : name{name}
	{
		publicKeyPath = name + "_public.pem";
		privateKeyPath = name + "_private.pem";
		RSACrypto::generateRSA_keys(publicKeyPath.c_str(), privateKeyPath.c_str());

		BIO* public_key_bio = BIO_new_file(publicKeyPath.c_str(), "rb");
		publicKey = PEM_read_bio_RSA_PUBKEY(public_key_bio, NULL, NULL, NULL);
		BIO_free(public_key_bio);

		BIO* private_key_bio = BIO_new_file(privateKeyPath.c_str(), "rb");
		privateKey = PEM_read_bio_RSAPrivateKey(private_key_bio, NULL, NULL, NULL);
		BIO_free(private_key_bio);

		AESKey = const_cast<unsigned char*>(AES::AESKey::getKey());
		AESEncryptedFile = name + "_AESEncrypted.bin";
		AESDecryptedFile = name + "_AESDecrypted.txt";
		RSAEncryptedFile = name + "_RSAEncrypted.bin";
		RSADecryptedFile = name + "_RSADecrypted.txt";
		AESHashEncryptedFile = name + "_AESHashEncrypted.bin";
		AESHashDecryptedFile = name + "_AESHashDecrypted.bin";
		RSAHashEncryptedFile = name + "_RSAHashEncrypted.bin";
		RSAHashDecryptedFile = name + "_RSAHashDecrypted.bin";
		RSASignature = name + "_RSASignature.bin";
		RSAVerification = name + "_RSAVerification.bin";
		Encrypted_SignedFile = name + "_Encrypted_SignedFile.bin";
		Decrypted_SignedFile = name + "_Decrypted_SignedFile.txt";
		Decrypted_VerifiedFile = name + "_Decrypted_VerifiedFile.txt";
	}

	CryptoClient::~CryptoClient()
	{
		std::remove(Decrypted_SignedFile.c_str());
		std::remove("File_Signed.bin");
	}

	// Definitions for getters
	std::string CryptoClient::getName() const { return name; }
	std::string CryptoClient::getPublicKeyPath() const { return publicKeyPath; }
	std::string CryptoClient::getPrivateKeyPath() const { return privateKeyPath; }
	std::string CryptoClient::getAESEncryptedFile() const { return AESEncryptedFile; }
	std::string CryptoClient::getAESDecryptedFile() const { return AESDecryptedFile; }
	std::string CryptoClient::getRSAEncryptedFile() const { return RSAEncryptedFile; }
	std::string CryptoClient::getRSADecryptedFile() const { return RSADecryptedFile; }
	std::string CryptoClient::getAESHashEncryptedFile() const { return AESHashEncryptedFile; }
	std::string CryptoClient::getAESHashDecryptedFile() const { return AESHashDecryptedFile; }
	std::string CryptoClient::getRSAHashEncryptedFile() const { return RSAHashEncryptedFile; }
	std::string CryptoClient::getRSAHashDecryptedFile() const { return RSAHashDecryptedFile; }
	std::string CryptoClient::getRSASignature() const { return RSASignature; }
	std::string CryptoClient::getRSAVerification() const { return RSAVerification; }
	std::string CryptoClient::getEncrypted_SignedFile() const { return Encrypted_SignedFile; }
	std::string CryptoClient::getDecrypted_VerifiedFile() const { return Decrypted_VerifiedFile; }

	RSA* CryptoClient::getPublicKey() const
	{
		return publicKey;
	}


	std::pair<std::string, bool> CryptoClient::AESEncryptData(const std::string& inputData)
	{
		return AES::AESEncryptData(inputData, AESEncryptedFile, AESKey);
	}

	std::pair<std::string, bool> CryptoClient::AESEncryptFile(const std::string& inputFile)
	{
		return AES::AESEncryptFile(inputFile, AESEncryptedFile, AESKey);
	}

	std::pair<std::string, bool> CryptoClient::AESDecryptData(const std::string& inputData)
	{
		return AES::AESDecryptData(inputData, AESDecryptedFile, AESKey);
	}

	std::pair<std::string, bool> CryptoClient::AESDecryptFile(const std::string& inputFile)
	{
		return AES::AESDecryptFile(inputFile, AESDecryptedFile, AESKey);
	}

	std::pair<std::string, bool> CryptoClient::AESEncryptAndHashFile(const std::string& inputFile)
	{
		return AES::AESEncryptAndHashFile(inputFile, AESEncryptedFile, AESHashEncryptedFile, AESKey);
	}

	std::pair<std::string, bool> CryptoClient::AESEncryptAndHashData(const std::string& inputData)
	{
		return AES::AESEncryptAndHashData(inputData, AESEncryptedFile, AESHashEncryptedFile, AESKey);
	}

	std::pair<std::string, bool> CryptoClient::AESDecryptAndHashFile(const std::string& inputFile, const std::string& hashFile)
	{
		return AES::AESDecryptAndHashFile(inputFile,AESDecryptedFile,hashFile,AESHashDecryptedFile,AESKey);
	}

	std::pair<std::string, bool> CryptoClient::AESDecryptAndHashData(const std::string& inputData, const std::string& hashFile)
	{
		return AES::AESDecryptAndHashData(inputData, AESDecryptedFile, hashFile, AESHashDecryptedFile, AESKey);
	}

	std::string CryptoClient::RSAEncryptData(const std::string& inputData, RSA* key, RSACrypto::KEY keyType)
	{
		return RSACrypto::RSAEncryptData(inputData,RSAEncryptedFile, key, keyType);
	}

	std::string CryptoClient::RSAEncryptData(const std::string& inputData, const std::string& keyPath, RSACrypto::KEY keyType)
	{
		return RSACrypto::RSAEncryptData(inputData, RSAEncryptedFile, keyPath, keyType);
	}

	std::string CryptoClient::RSAEncryptFile(const std::string& inputFile, RSA* key, RSACrypto::KEY keyType)
	{
		return RSACrypto::RSAEncryptFile(inputFile, RSAEncryptedFile, key, keyType);
	}

	std::string CryptoClient::RSAEncryptFile(const std::string& inputFile, const std::string& keyPath, RSACrypto::KEY keyType)
	{
		return RSACrypto::RSAEncryptFile(inputFile, RSAEncryptedFile, keyPath, keyType);
	}




	std::string CryptoClient::RSADecryptData(const std::string& inputData, RSA* key, RSACrypto::KEY keyType)
	{
		return RSACrypto::RSADecryptData(inputData, RSADecryptedFile, key, keyType);
	}

	std::string CryptoClient::RSADecryptData(const std::string& inputData, const std::string& keyPath, RSACrypto::KEY keyType)
	{
		return RSACrypto::RSADecryptData(inputData, RSADecryptedFile, keyPath, keyType);
	}

	std::string CryptoClient::RSADecryptFile(const std::string& inputFile, RSA* key, RSACrypto::KEY keyType)
	{
		return RSACrypto::RSADecryptFile(inputFile, RSADecryptedFile, key, keyType);
	}

	std::string CryptoClient::RSADecryptFile(const std::string& inputFile, const std::string& keyPath, RSACrypto::KEY keyType)
	{
		return RSACrypto::RSADecryptFile(inputFile, RSADecryptedFile, keyPath, keyType);
	}




	std::string CryptoClient::RSAEncryptAndHashFile(const std::string& inputFile, RSA* key, RSACrypto::KEY keyType)
	{
		if (keyType == RSACrypto::KEY::PUBLIC_KEY)
		{
			return RSACrypto::RSAEncryptAndHashFile(inputFile, RSAEncryptedFile, RSAHashEncryptedFile, key, keyType);
		}
		else if (keyType == RSACrypto::KEY::PRIVATE_KEY)
		{
			return RSACrypto::RSAEncryptAndHashFile(inputFile, RSAEncryptedFile, RSAHashEncryptedFile, privateKey, keyType);
		}
		return "Error. Missing Key";
	}

	std::string CryptoClient::RSAEncryptAndHashFile(const std::string& inputFile, const std::string& keyPath, RSACrypto::KEY keyType)
	{
		if (keyType == RSACrypto::KEY::PUBLIC_KEY)
		{
			return RSACrypto::RSAEncryptAndHashFile(inputFile, RSAEncryptedFile, RSAHashEncryptedFile, keyPath, keyType);
		}
		else if (keyType == RSACrypto::KEY::PRIVATE_KEY)
		{
			return RSACrypto::RSAEncryptAndHashFile(inputFile, RSAEncryptedFile, RSAHashEncryptedFile, privateKeyPath, keyType);
		}
		return "Error. Missing Key";
	}

	std::string CryptoClient::RSAEncryptAndHashData(const std::string& inputData, RSA* key, RSACrypto::KEY keyType)
	{
		if (keyType == RSACrypto::KEY::PUBLIC_KEY)
		{
			return RSACrypto::RSAEncryptAndHashData(inputData, RSAEncryptedFile, RSAHashEncryptedFile, key, keyType);
		}
		else if (keyType == RSACrypto::KEY::PRIVATE_KEY)
		{
			return RSACrypto::RSAEncryptAndHashData(inputData, RSAEncryptedFile, RSAHashEncryptedFile, privateKey, keyType);
		}
		return "Error. Missing Key";
	}

	std::string CryptoClient::RSAEncryptAndHashData(const std::string& inputData, const std::string& keyPath, RSACrypto::KEY keyType)
	{
		if (keyType == RSACrypto::KEY::PUBLIC_KEY)
		{
			return RSACrypto::RSAEncryptAndHashFile(inputData, RSAEncryptedFile, RSAHashEncryptedFile, keyPath, keyType);
		}
		else if (keyType == RSACrypto::KEY::PRIVATE_KEY)
		{
			return RSACrypto::RSAEncryptAndHashFile(inputData, RSAEncryptedFile, RSAHashEncryptedFile, privateKeyPath, keyType);
		}
		return "Error. Missing Key";
	}


	std::string CryptoClient::RSADecryptAndHashFile(const std::string& inputFile, const std::string& hashFile, RSA* key, RSACrypto::KEY keyType)
	{
		if (keyType == RSACrypto::KEY::PUBLIC_KEY)
		{
			return RSACrypto::RSADecryptAndHashFile(inputFile, RSADecryptedFile, hashFile, RSAHashDecryptedFile, key, keyType);
		}
		else if (keyType == RSACrypto::KEY::PRIVATE_KEY)
		{
			return RSACrypto::RSADecryptAndHashFile(inputFile, RSADecryptedFile, hashFile, RSAHashDecryptedFile, privateKey, keyType);
		}
		return "Error. Missing Key";
	}

	std::string CryptoClient::RSADecryptAndHashFile(const std::string& inputFile, const std::string& hashFile, const std::string& keyPath, RSACrypto::KEY keyType)
	{
		if (keyType == RSACrypto::KEY::PUBLIC_KEY)
		{
			return RSACrypto::RSADecryptAndHashFile(inputFile, RSADecryptedFile, hashFile, RSAHashDecryptedFile, keyPath, keyType);
		}
		else if (keyType == RSACrypto::KEY::PRIVATE_KEY)
		{
			return RSACrypto::RSADecryptAndHashFile(inputFile, RSADecryptedFile, hashFile, RSAHashDecryptedFile, privateKeyPath, keyType);
		}
		return "Error. Missing Key";
	}

	std::string CryptoClient::RSADecryptAndHashData(const std::string& inputData, const std::string& hashFile, RSA* key, RSACrypto::KEY keyType)
	{
		if (keyType == RSACrypto::KEY::PUBLIC_KEY)
		{
			return RSACrypto::RSADecryptAndHashData(inputData, RSADecryptedFile, hashFile, RSAHashDecryptedFile, key, keyType);
		}
		else if (keyType == RSACrypto::KEY::PRIVATE_KEY)
		{
			return RSACrypto::RSADecryptAndHashData(inputData, RSADecryptedFile, hashFile, RSAHashDecryptedFile, privateKey, keyType);
		}
		return "Error. Missing Key";
	}

	std::string CryptoClient::RSADecryptAndHashData(const std::string& inputData, const std::string& hashFile, const std::string& keyPath, RSACrypto::KEY keyType)
	{
		if (keyType == RSACrypto::KEY::PUBLIC_KEY)
		{
			return RSACrypto::RSADecryptAndHashData(inputData, RSADecryptedFile, hashFile, RSAHashDecryptedFile, keyPath, keyType);
		}
		else if (keyType == RSACrypto::KEY::PRIVATE_KEY)
		{
			return RSACrypto::RSADecryptAndHashData(inputData, RSADecryptedFile, hashFile, RSAHashDecryptedFile, privateKeyPath, keyType);
		}
		return "Error. Missing Key";
	}


	void CryptoClient::RSASignFile(const std::string& inputFile, RSA* key)
	{
		RSACrypto::RSASignFile(inputFile, RSASignature, key);
	}

	void CryptoClient::RSASignFile(const std::string& inputFile, const std::string& keyFile)
	{
		RSACrypto::RSASignFile(inputFile, RSASignature, keyFile);
	}

	void CryptoClient::RSASignData(const std::string& inputData, RSA* key)
	{
		RSACrypto::RSASignData(inputData, RSASignature, key);
	}

	void CryptoClient::RSASignData(const std::string& inputData, const std::string& keyFile)
	{
		RSACrypto::RSASignData(inputData, RSASignature, keyFile);
	}

	bool CryptoClient::RSAVerifyFile(const std::string& inputFile, RSA* key)
	{
		return RSACrypto::RSAVerifyFile(inputFile, RSAVerification, key);
	}

	bool CryptoClient::RSAVerifyFile(const std::string& inputFile, const std::string& keyFile)
	{
		return RSACrypto::RSAVerifyFile(inputFile, RSAVerification, keyFile);
	}

	bool CryptoClient::RSAVerifyData(const std::string& inputData, RSA* key)
	{
		return RSACrypto::RSAVerifyData(inputData, RSAVerification, key);
	}

	bool CryptoClient::RSAVerifyData(const std::string& inputData, const std::string& keyFile)
	{
		return RSACrypto::RSAVerifyData(inputData, RSAVerification, keyFile);
	}



	std::pair<std::string, bool> CryptoClient::SignAndEncryptFile(const std::string& inputFile, const std::string& keyFile)
	{
		RSACrypto::RSASignFile(inputFile, RSASignature, keyFile);

		std::ifstream RSASignatureFile(RSASignature, std::ios::binary);
		if (!RSASignatureFile)
		{
			std::cerr << "Error opening file.\n";
			return std::make_pair("Error opening File.", false);
		}
		std::string RSASignatureStr((std::istreambuf_iterator<char>(RSASignatureFile)), std::istreambuf_iterator<char>());
		RSASignatureFile.close();

		// Read the content of the original file
		std::ifstream inFile(inputFile, std::ios::binary);
		if (!inFile)
		{
			std::cerr << "Error opening file.\n";
			return std::make_pair("Error opening File.", false);
		}
		std::string fileContent((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
		inFile.close();

		// Save both the RSA signature and the original file content to a new file
		std::ofstream SignedFile("File_Signed.bin", std::ios::binary);
		if (!SignedFile)
		{
			std::cerr << "Error opening file.\n";
			return std::make_pair("Error opening File.", false);
		}

		// Write the RSA signature to the new file
		SignedFile.write(RSASignatureStr.c_str(), RSASignatureStr.size());

		// Write the original file content to the new file
		SignedFile.write(fileContent.c_str(), fileContent.size());

		SignedFile.close();

		auto encryptionResult = AES::AESEncryptFile("File_Signed.bin", Encrypted_SignedFile, AESKey);

		// Check if encryption was successful
		if (!encryptionResult.second)
		{
			// Return an error message if encryption failed
			return std::make_pair("Error during AES encryption.", false);
		}

		std::pair<std::string, bool> encrypt = AES::AESEncryptFile("File_Signed.bin", Encrypted_SignedFile, AESKey);

		std::remove("File_Signedd.bin");

		return encrypt;
	}

	std::pair<std::string, bool> CryptoClient::SignAndEncryptData(const std::string& inputData, const std::string& keyFile)
	{
		RSACrypto::RSASignData(inputData, RSASignature, keyFile);

		std::ifstream RSASignatureFile(RSASignature, std::ios::binary);
		if (!RSASignatureFile)
		{
			std::cerr << "Error opening file.\n";
			return std::make_pair("Error opening File.", false);
		}
		std::string RSASignatureStr((std::istreambuf_iterator<char>(RSASignatureFile)), std::istreambuf_iterator<char>());
		RSASignatureFile.close();

		// Save both the RSA signature and the original file content to a new file
		std::ofstream SignedFile("File_Signed.bin", std::ios::binary);
		if (!SignedFile)
		{
			std::cerr << "Error opening file.\n";
			return std::make_pair("Error opening File.", false);
		}

		// Write the RSA signature to the new file
		SignedFile.write(RSASignatureStr.c_str(), RSASignatureStr.size());

		// Write the original file content to the new file
		SignedFile.write(inputData.c_str(), inputData.size());

		SignedFile.close();

		auto encryptionResult = AES::AESEncryptFile("File_Signed.bin", Encrypted_SignedFile, AESKey);

		// Check if encryption was successful
		if (!encryptionResult.second)
		{
			// Return an error message if encryption failed
			return std::make_pair("Error during AES encryption.", false);
		}

		std::pair<std::string, bool> encrypt = AES::AESEncryptFile("File_Signed.bin", Encrypted_SignedFile, AESKey);

		std::remove("File_Signed.bin");

		return encrypt;
	}


	std::pair<std::string, bool> CryptoClient::DecryptAndVerifyFile(const std::string& inputFile, const std::string& keyFile)
	{
		auto decryptionResult = AES::AESDecryptFile(inputFile, Decrypted_SignedFile, AESKey);

		// Check if decryption was successful
		if (!decryptionResult.second)
		{
			// Return an error message if decryption failed
			return std::make_pair("Error during AES decryption.", false);
		}

		std::string data = decryptionResult.first;

		// Extract the signature from the end of the decrypted file
		std::string decryptedData = data.substr(RSA_LENGTH);

		std::string encryptedHash = data.erase(RSA_LENGTH);

		if (RSACrypto::RSAVerifyData(encryptedHash, RSAVerification, keyFile))
		{
			// Read the content of the original file
			std::ifstream RSAVerificationFile(RSAVerification, std::ios::binary);
			if (!RSAVerificationFile)
			{
				std::cerr << "Error opening File.\n";
				return std::make_pair("Error opening File.", false);
			}
			std::string decryptedHash((std::istreambuf_iterator<char>(RSAVerificationFile)), std::istreambuf_iterator<char>());
			RSAVerificationFile.close();

			std::string computedHash = hashSHA512::computeSHA512(reinterpret_cast<const unsigned char*>(decryptedData.c_str()), decryptedData.size());

			// Compare the stored hash with the computed hash
			if (decryptedHash != computedHash)
			{
				std::cerr << "Hash mismatch. File may have been tampered with.\n";
				return std::make_pair("Hash mismatch. File may have been tampered with.", false);
			}
			else
			{
				std::cout << "No Data Corruption in File" << std::endl;
			}

			std::ofstream DecryptedFile(Decrypted_VerifiedFile, std::ios::binary);
			if (!DecryptedFile)
			{
				std::cerr << "Error opening file.\n";
				return std::make_pair("Error opening File.", false);
			}

			// Write the RSA signature to the new file
			DecryptedFile.write(decryptedData.c_str(), decryptedData.size());

			// Return the decrypted data and true indicating success
			return std::make_pair(decryptedData, true);
		}
		else
		{
			// Return an error message if verification failed
			return std::make_pair("ERROR in Verification", false);
		}
	}

	void CryptoClient::generateAESKey()
	{
		AES::AESKey::generateKey();
		AESKey = const_cast<unsigned char*>(AES::AESKey::getKey());
	}


	void CryptoClient::generateRSAKeys()
	{
		RSACrypto::generateRSA_keys(publicKeyPath.c_str(), privateKeyPath.c_str());

		BIO* public_key_bio = BIO_new_file(publicKeyPath.c_str(), "rb");
		publicKey = PEM_read_bio_RSA_PUBKEY(public_key_bio, NULL, NULL, NULL);
		BIO_free(public_key_bio);

		BIO* private_key_bio = BIO_new_file(privateKeyPath.c_str(), "rb");
		privateKey = PEM_read_bio_RSAPrivateKey(private_key_bio, NULL, NULL, NULL);
		BIO_free(private_key_bio);
	}

}
