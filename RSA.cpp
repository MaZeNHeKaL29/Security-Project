#include "RSA.h"
#include "SHA512.h"

namespace RSACrypto
{
    void handleErrors() {
        //ERR_print_errors_fp(stderr);
        std::cerr << "Error occurred.\n";
    }

    std::string readFileContent(const std::string& filePath)
    {
        std::ifstream file(filePath, std::ios::binary);
        return { std::istreambuf_iterator<char>(file), {} };
    }

    void writeFileContent(const std::string& filePath, const std::string& content)
    {
        std::ofstream file(filePath, std::ios::binary);
        file << content;
    }

    void generateRSA_keys(const char* public_key_filename, const char* private_key_filename)
    {
        OSSL_LIB_CTX* libctx = OSSL_LIB_CTX_new();
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", NULL);

        if (EVP_PKEY_keygen_init(pctx) <= 0) {
            std::cerr << "Failed to initialize key generation." << std::endl;
        }

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0) {
            std::cerr << "Failed to set key length." << std::endl;
        }

        EVP_PKEY* pkey = NULL;
        if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
            std::cerr << "Failed to generate key pair." << std::endl;
        }

        BIO* bio = BIO_new_file(public_key_filename, "wb");
        if (PEM_write_bio_PUBKEY(bio, pkey) != 1) {
            std::cerr << "Failed to write public key." << std::endl;
        }
        BIO_free(bio);

        bio = BIO_new_file(private_key_filename, "wb");
        if (PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
            std::cerr << "Failed to write private key." << std::endl;
        }
        BIO_free(bio);

        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        OSSL_LIB_CTX_free(libctx);
    }



    std::string RSAEncryptData(const std::string& inputData, const std::string& outputFile, const std::string& keyFile, KEY keyType)
    {

        BIO* keyBio = BIO_new_file(keyFile.c_str(), "rb");
        RSA* key = keyType == KEY::PRIVATE_KEY ? PEM_read_bio_RSAPrivateKey(keyBio, NULL, NULL, NULL) : PEM_read_bio_RSA_PUBKEY(keyBio, NULL, NULL, NULL);
        BIO_free(keyBio);

        if (!key)
        {
            handleErrors();
            return "Error reading RSA key.";
        }

        size_t rsa_len = RSA_size(key);

        std::string encryptedData(rsa_len, '\0');
        int result = 0;
        if (keyType == KEY::PUBLIC_KEY)
        {
            result = RSA_public_encrypt(static_cast<int>(inputData.size()), reinterpret_cast<const unsigned char*>(inputData.c_str()),
                reinterpret_cast<unsigned char*>(&encryptedData[0]), key, RSA_PKCS1_OAEP_PADDING);
        }
        else if (keyType == KEY::PRIVATE_KEY)
        {
            result = RSA_private_encrypt(static_cast<int>(inputData.size()), reinterpret_cast<const unsigned char*>(inputData.c_str()),
                reinterpret_cast<unsigned char*>(&encryptedData[0]), key, RSA_PKCS1_PADDING);
        }

        if (result <= 0)
        {
            handleErrors();
            RSA_free(key);
            return "Error decrypting data.";
        }

        RSA_free(key);

        std::ofstream encryptedFile(outputFile, std::ios::binary);
        encryptedFile.write(encryptedData.c_str(), encryptedData.size());
        encryptedFile.close();

        return encryptedData;
    }

    std::string RSAEncryptData(const std::string& inputData, const std::string& outputFile, RSA* key, KEY keyType)
    {
        if (!key)
        {
            handleErrors();
            return "Error reading RSA key.";
        }

        size_t rsa_len = RSA_size(key);

        std::string encryptedData(rsa_len, '\0');
        int result = 0;
        if (keyType == KEY::PUBLIC_KEY)
        {
            result = RSA_public_encrypt(static_cast<int>(inputData.size()), reinterpret_cast<const unsigned char*>(inputData.c_str()),
                reinterpret_cast<unsigned char*>(&encryptedData[0]), key, RSA_PKCS1_OAEP_PADDING);
        }
        else if (keyType == KEY::PRIVATE_KEY)
        {
            result = RSA_private_encrypt(static_cast<int>(inputData.size()), reinterpret_cast<const unsigned char*>(inputData.c_str()),
                reinterpret_cast<unsigned char*>(&encryptedData[0]), key, RSA_PKCS1_PADDING);
        }

        if (result <= 0)
        {
            handleErrors();
            return "Error decrypting data.";
        }

        std::ofstream encryptedFile(outputFile, std::ios::binary);
        encryptedFile.write(encryptedData.c_str(), encryptedData.size());
        encryptedFile.close();

        return encryptedData;
    }

    std::string RSAEncryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& keyFile, KEY keyType)
    {
        std::ifstream inFile(inputFile, std::ios::binary);
        if (!inFile)
        {
            std::cerr << "Error opening File.\n";
            return "Error opening File.";
        }
        std::string inputData((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
        inFile.close();


        BIO* keyBio = BIO_new_file(keyFile.c_str(), "rb");
        RSA* key = keyType == KEY::PRIVATE_KEY ? PEM_read_bio_RSAPrivateKey(keyBio, NULL, NULL, NULL) : PEM_read_bio_RSA_PUBKEY(keyBio, NULL, NULL, NULL);
        BIO_free(keyBio);

        if (!key)
        {
            handleErrors();
            return "Error reading RSA key.";
        }

        size_t rsa_len = RSA_size(key);

        std::string encryptedData(rsa_len, '\0');
        int result = 0;
        if (keyType == KEY::PUBLIC_KEY)
        {
            result = RSA_public_encrypt(static_cast<int>(inputData.size()), reinterpret_cast<const unsigned char*>(inputData.c_str()),
                reinterpret_cast<unsigned char*>(&encryptedData[0]), key, RSA_PKCS1_OAEP_PADDING);
        }
        else if (keyType == KEY::PRIVATE_KEY)
        {
            result = RSA_private_encrypt(static_cast<int>(inputData.size()), reinterpret_cast<const unsigned char*>(inputData.c_str()),
                reinterpret_cast<unsigned char*>(&encryptedData[0]), key, RSA_PKCS1_PADDING);
        }

        if (result <= 0)
        {
            handleErrors();
            RSA_free(key);
            return "Error decrypting data.";
        }

        RSA_free(key);


        std::ofstream encryptedFile(outputFile, std::ios::binary);
        encryptedFile.write(encryptedData.c_str(), encryptedData.size());
        encryptedFile.close();

        return encryptedData;
    }

    std::string RSAEncryptFile(const std::string& inputFile, const std::string& outputFile, RSA* key, KEY keyType)
    {
        std::ifstream inFile(inputFile, std::ios::binary);
        if (!inFile)
        {
            std::cerr << "Error opening File.\n";
            return "Error opening File.";
        }
        std::string inputData((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
        inFile.close();

        if (!key)
        {
            handleErrors();
            return "Error reading RSA key.";
        }

        size_t rsa_len = RSA_size(key);

        std::string encryptedData(rsa_len, '\0');
        int result = 0;
        if (keyType == KEY::PUBLIC_KEY)
        {
            result = RSA_public_encrypt(static_cast<int>(inputData.size()), reinterpret_cast<const unsigned char*>(inputData.c_str()),
                reinterpret_cast<unsigned char*>(&encryptedData[0]), key, RSA_PKCS1_OAEP_PADDING);
        }
        else if (keyType == KEY::PRIVATE_KEY)
        {
            result = RSA_private_encrypt(static_cast<int>(inputData.size()), reinterpret_cast<const unsigned char*>(inputData.c_str()),
                reinterpret_cast<unsigned char*>(&encryptedData[0]), key, RSA_PKCS1_PADDING);
        }

        if (result <= 0)
        {
            handleErrors();
            return "Error decrypting data.";
        }


        std::ofstream encryptedFile(outputFile, std::ios::binary);
        encryptedFile.write(encryptedData.c_str(), encryptedData.size());
        encryptedFile.close();

        return encryptedData;
    }







    std::string RSADecryptData(const std::string& inputData, const std::string& outputFile, const std::string& keyFile, KEY keyType)
    {
        BIO* keyBio = BIO_new_file(keyFile.c_str(), "rb");
        RSA* key = keyType == KEY::PRIVATE_KEY ? PEM_read_bio_RSAPrivateKey(keyBio, NULL, NULL, NULL) : PEM_read_bio_RSA_PUBKEY(keyBio, NULL, NULL, NULL);
        BIO_free(keyBio);


        if (!key)
        {
            handleErrors();
            return "Error reading RSA key.";
        }

        size_t rsa_len = RSA_size(key);

        std::string decryptedData(rsa_len, '\0');
        int result = 0;
        if (keyType == KEY::PUBLIC_KEY)
        {
            result = RSA_public_decrypt(static_cast<int>(inputData.size()), reinterpret_cast<const unsigned char*>(inputData.c_str()),
                reinterpret_cast<unsigned char*>(&decryptedData[0]), key, RSA_PKCS1_PADDING);
        }
        else if (keyType == KEY::PRIVATE_KEY)
        {
            result = RSA_private_decrypt(static_cast<int>(inputData.size()), reinterpret_cast<const unsigned char*>(inputData.c_str()),
                reinterpret_cast<unsigned char*>(&decryptedData[0]), key, RSA_PKCS1_OAEP_PADDING);
        }

        if (result <= 0)
        {
            handleErrors();
            RSA_free(key);
            return "Error decrypting data.";
        }

        RSA_free(key);

        //remove padding
        while (decryptedData.back() == '\0')
        {
            decryptedData.pop_back();
        }

        std::ofstream decryptedFile(outputFile, std::ios::binary);
        decryptedFile.write(decryptedData.c_str(), decryptedData.size());
        decryptedFile.close();

        return decryptedData;
    }

    std::string RSADecryptData(const std::string& inputData, const std::string& outputFile, RSA* key, KEY keyType)
    {
        if (!key)
        {
            handleErrors();
            return "Error reading RSA key.";
        }

        size_t rsa_len = RSA_size(key);

        std::string decryptedData(rsa_len, '\0');
        int result = 0;
        if (keyType == KEY::PUBLIC_KEY)
        {
            result = RSA_public_decrypt(static_cast<int>(inputData.size()), reinterpret_cast<const unsigned char*>(inputData.c_str()),
                reinterpret_cast<unsigned char*>(&decryptedData[0]), key, RSA_PKCS1_PADDING);
        }
        else if (keyType == KEY::PRIVATE_KEY)
        {
            result = RSA_private_decrypt(static_cast<int>(inputData.size()), reinterpret_cast<const unsigned char*>(inputData.c_str()),
                reinterpret_cast<unsigned char*>(&decryptedData[0]), key, RSA_PKCS1_OAEP_PADDING);
        }

        if (result <= 0)
        {
            handleErrors();
            return "Error decrypting data.";
        }


        //remove padding
        while (decryptedData.back() == '\0')
        {
            decryptedData.pop_back();
        }

        std::ofstream decryptedFile(outputFile, std::ios::binary);
        decryptedFile.write(decryptedData.c_str(), decryptedData.size());
        decryptedFile.close();

        return decryptedData;
    }

    std::string RSADecryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& keyFile, KEY keyType)
    {
        std::ifstream inFile(inputFile, std::ios::binary);
        if (!inFile)
        {
            std::cerr << "Error opening File.\n";
            return "Error opening File.";
        }
        std::string inputData((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
        inFile.close();

        BIO* keyBio = BIO_new_file(keyFile.c_str(), "rb");
        RSA* key = keyType == KEY::PRIVATE_KEY ? PEM_read_bio_RSAPrivateKey(keyBio, NULL, NULL, NULL) : PEM_read_bio_RSA_PUBKEY(keyBio, NULL, NULL, NULL);
        BIO_free(keyBio);


        if (!key)
        {
            handleErrors();
            return "Error reading RSA key.";
        }

        size_t rsa_len = RSA_size(key);

        std::string decryptedData(rsa_len, '\0');
        int result = 0;
        if (keyType == KEY::PUBLIC_KEY)
        {
            result = RSA_public_decrypt(static_cast<int>(inputData.size()), reinterpret_cast<const unsigned char*>(inputData.c_str()),
                reinterpret_cast<unsigned char*>(&decryptedData[0]), key, RSA_PKCS1_PADDING);
        }
        else if (keyType == KEY::PRIVATE_KEY)
        {
            result = RSA_private_decrypt(static_cast<int>(inputData.size()), reinterpret_cast<const unsigned char*>(inputData.c_str()),
                reinterpret_cast<unsigned char*>(&decryptedData[0]), key, RSA_PKCS1_OAEP_PADDING);
        }

        if (result <= 0)
        {
            handleErrors();
            RSA_free(key);
            return "Error decrypting data.";
        }

        RSA_free(key);


        //remove padding
        while (decryptedData.back() == '\0')
        {
            decryptedData.pop_back();
        }

        std::ofstream decryptedFile(outputFile, std::ios::binary);
        decryptedFile.write(decryptedData.c_str(), decryptedData.size());
        decryptedFile.close();

        return decryptedData;
    }

    std::string RSADecryptFile(const std::string& inputFile, const std::string& outputFile, RSA* key, KEY keyType)
    {
        std::ifstream inFile(inputFile, std::ios::binary);
        if (!inFile)
        {
            std::cerr << "Error opening File.\n";
            return "Error opening File.";
        }
        std::string inputData((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
        inFile.close();


        if (!key)
        {
            handleErrors();
            return "Error reading RSA key.";
        }

        size_t rsa_len = RSA_size(key);

        std::string decryptedData(rsa_len, '\0');
        int result = 0;
        if (keyType == KEY::PUBLIC_KEY)
        {
            result = RSA_public_decrypt(static_cast<int>(inputData.size()), reinterpret_cast<const unsigned char*>(inputData.c_str()),
                reinterpret_cast<unsigned char*>(&decryptedData[0]), key, RSA_PKCS1_PADDING);
        }
        else if (keyType == KEY::PRIVATE_KEY)
        {
            result = RSA_private_decrypt(static_cast<int>(inputData.size()), reinterpret_cast<const unsigned char*>(inputData.c_str()),
                reinterpret_cast<unsigned char*>(&decryptedData[0]), key, RSA_PKCS1_OAEP_PADDING);
        }

        if (result <= 0)
        {
            handleErrors();
            return "Error decrypting data.";
        }

        //remove padding
        while (decryptedData.back() == '\0')
        {
            decryptedData.pop_back();
        }

        std::ofstream decryptedFile(outputFile, std::ios::binary);
        decryptedFile.write(decryptedData.c_str(), decryptedData.size());
        decryptedFile.close();

        return decryptedData;
    }

    std::string RSAEncryptAndHashFile(const std::string& inputFile, const std::string& outputFile, const std::string& hashFile, const std::string& keyFile, KEY keyType)
    {
        // Compute and write the SHA-512 hash of the encrypted file
        std::string FileContent = readFileContent(inputFile);
        std::string hash = hashSHA512::computeSHA512(reinterpret_cast<const unsigned char*>(FileContent.c_str()), FileContent.size());
        RSAEncryptData(hash, hashFile, keyFile, keyType);


        return RSAEncryptFile(inputFile, outputFile, keyFile, keyType);
    }

    std::string RSAEncryptAndHashFile(const std::string& inputFile, const std::string& outputFile, const std::string& hashFile, RSA* key, KEY keyType)
    {
        // Compute and write the SHA-512 hash of the encrypted file
        std::string FileContent = readFileContent(inputFile);
        std::string hash = hashSHA512::computeSHA512(reinterpret_cast<const unsigned char*>(FileContent.c_str()), FileContent.size());
        RSAEncryptData(hash, hashFile, key, keyType);


        return RSAEncryptFile(inputFile, outputFile, key, keyType);
    }

    std::string RSAEncryptAndHashData(const std::string& inputData, const std::string& outputFile, const std::string& hashFile, const std::string& keyFile, KEY keyType)
    {
        std::string hash = hashSHA512::computeSHA512(reinterpret_cast<const unsigned char*>(inputData.c_str()), inputData.size());
        RSAEncryptData(hash, hashFile, keyFile, keyType);


        return RSAEncryptData(inputData, outputFile, keyFile, keyType);
    }

    std::string RSAEncryptAndHashData(const std::string& inputData, const std::string& outputFile, const std::string& hashFile, RSA* key, KEY keyType)
    {
        std::string hash = hashSHA512::computeSHA512(reinterpret_cast<const unsigned char*>(inputData.c_str()), inputData.size());
        RSAEncryptData(hash, hashFile, key, keyType);


        return RSAEncryptData(inputData, outputFile, key, keyType);
    }

    std::string RSADecryptAndHashFile(const std::string& inputFile, const std::string& outputFile, const std::string& hashEncryptedFile, const std::string& hashDecryptedFile, const std::string& keyFile, KEY keyType)
    {
        RSADecryptFile(hashEncryptedFile, hashDecryptedFile, keyFile, keyType);

        // Read the stored hash from the hash file
        std::ifstream hashFileR(hashDecryptedFile, std::ios::binary);
        std::string storedHash((std::istreambuf_iterator<char>(hashFileR)), {});
        hashFileR.close();

        std::string decryptedStr = RSADecryptFile(inputFile, outputFile, keyFile, keyType);

        // Compute the SHA-512 hash of the decrypted file
        std::string decryptedFileContent = readFileContent(outputFile);
        std::string computedHash = hashSHA512::computeSHA512(reinterpret_cast<const unsigned char*>(decryptedFileContent.c_str()), decryptedFileContent.size());

        // Compare the stored hash with the computed hash
        if (storedHash != computedHash)
        {
            std::cerr << "Hash mismatch. File may have been tampered with.\n";
        }
        else
        {
            std::cout << "No Data Corruption in File\n" << std::endl;
        }

        return decryptedStr;
    }

    std::string RSADecryptAndHashFile(const std::string& inputFile, const std::string& outputFile, const std::string& hashEncryptedFile, const std::string& hashDecryptedFile, RSA* key, KEY keyType)
    {
        RSADecryptFile(hashEncryptedFile, hashDecryptedFile, key, keyType);

        // Read the stored hash from the hash file
        std::ifstream hashFileR(hashDecryptedFile, std::ios::binary);
        std::string storedHash((std::istreambuf_iterator<char>(hashFileR)), {});
        hashFileR.close();

        std::string decryptedStr = RSADecryptFile(inputFile, outputFile, key, keyType);

        // Compute the SHA-512 hash of the decrypted file
        std::string decryptedFileContent = readFileContent(outputFile);
        std::string computedHash = hashSHA512::computeSHA512(reinterpret_cast<const unsigned char*>(decryptedFileContent.c_str()), decryptedFileContent.size());

        // Compare the stored hash with the computed hash
        if (storedHash != computedHash)
        {
            std::cerr << "Hash mismatch. File may have been tampered with.\n";
        }
        else
        {
            std::cout << "No Data Corruption in File\n" << std::endl;
        }

        return decryptedStr;
    }


    std::string RSADecryptAndHashData(const std::string& inputData, const std::string& outputFile, const std::string& hashEncryptedFile, const std::string& hashDecryptedFile, const std::string& keyFile, KEY keyType)
    {
        RSADecryptFile(hashEncryptedFile, hashDecryptedFile, keyFile, keyType);

        // Read the stored hash from the hash file
        std::ifstream hashFileR(hashDecryptedFile, std::ios::binary);
        std::string storedHash((std::istreambuf_iterator<char>(hashFileR)), {});
        hashFileR.close();

        std::string decryptedStr = RSADecryptData(inputData, outputFile, keyFile, keyType);

        // Compute the SHA-512 hash of the decrypted file
        std::string decryptedFileContent = readFileContent(outputFile);
        std::string computedHash = hashSHA512::computeSHA512(reinterpret_cast<const unsigned char*>(decryptedFileContent.c_str()), decryptedFileContent.size());

        // Compare the stored hash with the computed hash
        if (storedHash != computedHash)
        {
            std::cerr << "Hash mismatch. File may have been tampered with.\n";
        }
        else
        {
            std::cout << "No Data Corruption in File\n" << std::endl;
        }

        return decryptedStr;
    }

    std::string RSADecryptAndHashData(const std::string& inputData, const std::string& outputFile, const std::string& hashEncryptedFile, const std::string& hashDecryptedFile, RSA* key, KEY keyType)
    {
        RSADecryptFile(hashEncryptedFile, hashDecryptedFile, key, keyType);

        // Read the stored hash from the hash file
        std::ifstream hashFileR(hashDecryptedFile, std::ios::binary);
        std::string storedHash((std::istreambuf_iterator<char>(hashFileR)), {});
        hashFileR.close();

        std::string decryptedStr = RSADecryptData(inputData, outputFile, key, keyType);

        // Compute the SHA-512 hash of the decrypted file
        std::string decryptedFileContent = readFileContent(outputFile);
        std::string computedHash = hashSHA512::computeSHA512(reinterpret_cast<const unsigned char*>(decryptedFileContent.c_str()), decryptedFileContent.size());

        // Compare the stored hash with the computed hash
        if (storedHash != computedHash)
        {
            std::cerr << "Hash mismatch. File may have been tampered with.\n";
        }
        else
        {
            std::cout << "No Data Corruption in File\n" << std::endl;
        }

        return decryptedStr;
    }




    void RSASignFile(const std::string& inputFile, const std::string& outputFile, RSA* key)
    {
        std::string FileContent = readFileContent(inputFile);
        std::string computedHash = hashSHA512::computeSHA512(reinterpret_cast<const unsigned char*>(FileContent.c_str()), FileContent.size());

        RSAEncryptData(computedHash, outputFile, key, KEY::PRIVATE_KEY);
    }



    void RSASignFile(const std::string& inputFile, const std::string& outputFile, const std::string& keyFile)
    {
        std::string FileContent = readFileContent(inputFile);
        std::string computedHash = hashSHA512::computeSHA512(reinterpret_cast<const unsigned char*>(FileContent.c_str()), FileContent.size());

        RSAEncryptData(computedHash, outputFile, keyFile, KEY::PRIVATE_KEY);
    }


    void RSASignData(const std::string& inputData, const std::string& outputFile, RSA* key)
    {
        std::string computedHash = hashSHA512::computeSHA512(reinterpret_cast<const unsigned char*>(inputData.c_str()), inputData.size());

        RSAEncryptData(computedHash, outputFile, key, KEY::PRIVATE_KEY);
    }

    void RSASignData(const std::string& inputData, const std::string& outputFile, const std::string& keyFile)
    {
        std::string computedHash = hashSHA512::computeSHA512(reinterpret_cast<const unsigned char*>(inputData.c_str()), inputData.size());

        RSAEncryptData(computedHash, outputFile, keyFile, KEY::PRIVATE_KEY);
    }


    bool RSAVerifyFile(const std::string& inputFile, const std::string& outputFile, RSA* key)
    {
        std::string verify = RSADecryptFile(inputFile, outputFile, key, KEY::PUBLIC_KEY);
        if (verify == "Error opening File."
            || verify == "Error reading RSA key."
            || verify == "Error decrypting data.")
        {
            return false;
        }

        return true; 
    }


    bool RSAVerifyFile(const std::string& inputFile, const std::string& outputFile, const std::string& keyFile)
    {
        std::string verify = RSADecryptFile(inputFile, outputFile, keyFile, KEY::PUBLIC_KEY);
        if (verify == "Error opening File."
            || verify == "Error reading RSA key."
            || verify == "Error decrypting data.")
        {
            return false;
        }

        return true;
    }


    bool RSAVerifyData(const std::string& inputData, const std::string& outputFile, RSA* key)
    {
        std::string verify = RSADecryptData(inputData, outputFile, key, KEY::PUBLIC_KEY);
        if (verify == "Error opening File."
            || verify == "Error reading RSA key."
            || verify == "Error decrypting data.")
        {
            return false;
        }

        return true;
    }


    bool RSAVerifyData(const std::string& inputData, const std::string& outputFile, const std::string& keyFile)
    {
        std::string verify = RSADecryptData(inputData, outputFile, keyFile, KEY::PUBLIC_KEY);
        if (verify == "Error opening File."
            || verify == "Error reading RSA key."
            || verify == "Error decrypting data.")
        {
            return false;
        }

        return true;
    }
}