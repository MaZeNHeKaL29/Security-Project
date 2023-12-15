#include "AES.h"
#include "SHA512.h"


namespace AES
{
    unsigned char AESKey::key[32];

    void handleErrors()
    {
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

    std::pair<std::string, bool> AESEncryptData(const std::string& inputData, const std::string& outputFile, const unsigned char* key)
    {
        const int bufferSize = 4096;
        unsigned char iv[AES_BLOCK_SIZE];
        unsigned char inBuffer[bufferSize + AES_BLOCK_SIZE];
        unsigned char outBuffer[bufferSize + AES_BLOCK_SIZE];

        std::ostringstream outStream;

        // Use std::istringstream to treat inputData as a stream
        std::istringstream inStream(inputData, std::ios::binary);
        std::ofstream outFile(outputFile, std::ios::binary);

        if (!outFile)
        {
            std::cerr << "Error opening File.\n";
            return std::make_pair("Error opening File.", false);
        }

        RAND_bytes(iv, AES_BLOCK_SIZE);
        outFile.write(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);
        outStream.write(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);

        EVP_CIPHER_CTX* ctx;
        ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);

        int bytesRead, cipherLen, outLen;
        while ((bytesRead = inStream.read(reinterpret_cast<char*>(inBuffer), bufferSize + AES_BLOCK_SIZE).gcount()) > 0)
        {
            if (!EVP_EncryptUpdate(ctx, outBuffer, &outLen, inBuffer, bytesRead))
            {
                handleErrors();
                EVP_CIPHER_CTX_free(ctx);
                outFile.close();
                return std::make_pair("Error", false);
            }
            outFile.write(reinterpret_cast<char*>(outBuffer), outLen);
            outStream.write(reinterpret_cast<char*>(outBuffer), outLen);
        }

        if (!EVP_EncryptFinal_ex(ctx, outBuffer, &outLen))
        {
            handleErrors();
            EVP_CIPHER_CTX_free(ctx);
            outFile.close();
            return std::make_pair("Error", false);
        }
        outFile.write(reinterpret_cast<char*>(outBuffer), outLen);
        outStream.write(reinterpret_cast<char*>(outBuffer), outLen);

        EVP_CIPHER_CTX_free(ctx);

        outFile.close();

        return std::make_pair(outStream.str(), true);
    }


    std::pair<std::string, bool> AESEncryptFile(const std::string& inputFile, const std::string& outputFile, const unsigned char* key)
    {
        const int bufferSize = 4096;
        unsigned char iv[AES_BLOCK_SIZE];
        unsigned char inBuffer[bufferSize + AES_BLOCK_SIZE];
        unsigned char outBuffer[bufferSize + AES_BLOCK_SIZE];
        std::ifstream inFile(inputFile, std::ios::binary);
        std::ofstream outFile(outputFile, std::ios::binary);
        std::ostringstream outStream;

        if (!inFile || !outFile)
        {
            std::cerr << "Error File.\n";
            return std::make_pair("Error File.", false);
        }

        RAND_bytes(iv, AES_BLOCK_SIZE);
        outFile.write(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);
        outStream.write(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);

        EVP_CIPHER_CTX* ctx;
        ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);

        int bytesRead, cipherLen, outLen;
        while ((bytesRead = inFile.read(reinterpret_cast<char*>(inBuffer), bufferSize + AES_BLOCK_SIZE).gcount()) > 0)
        {
            if (!EVP_EncryptUpdate(ctx, outBuffer, &outLen, inBuffer, bytesRead))
            {
                EVP_CIPHER_CTX_free(ctx);
                inFile.close();
                outFile.close();
                return std::make_pair("Error", false);
            }
            outFile.write(reinterpret_cast<char*>(outBuffer), outLen);
            outStream.write(reinterpret_cast<char*>(outBuffer), outLen);
        }

        if (!EVP_EncryptFinal_ex(ctx, outBuffer, &outLen))
        {
            EVP_CIPHER_CTX_free(ctx);
            inFile.close();
            outFile.close();
            return std::make_pair("Error", false);
        }
        outFile.write(reinterpret_cast<char*>(outBuffer), outLen);
        outStream.write(reinterpret_cast<char*>(outBuffer), outLen);

        EVP_CIPHER_CTX_free(ctx);

        inFile.close();
        outFile.close();

        return std::make_pair(outStream.str(), true);
    }


    std::pair<std::string, bool> AESDecryptData(const std::string& inputData, const std::string& outputFile, const unsigned char* key)
    {
        const int bufferSize = 4096;
        unsigned char iv[AES_BLOCK_SIZE];
        unsigned char inBuffer[bufferSize + AES_BLOCK_SIZE];
        unsigned char outBuffer[bufferSize + AES_BLOCK_SIZE];

        std::ostringstream outStream;

        // Use std::istringstream to treat inputData as a stream
        std::istringstream inStream(inputData, std::ios::binary);
        std::ofstream outFile(outputFile, std::ios::binary);

        if (!outFile)
        {
            std::cerr << "Error opening File.\n";
            return std::make_pair("Error opening File.", false);
        }

        inStream.read(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);

        EVP_CIPHER_CTX* ctx;
        ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);

        int bytesRead, plainLen, outLen;
        while ((bytesRead = inStream.read(reinterpret_cast<char*>(inBuffer), bufferSize + AES_BLOCK_SIZE).gcount()) > 0)
        {
            if (!EVP_DecryptUpdate(ctx, outBuffer, &outLen, inBuffer, bytesRead))
            {
                EVP_CIPHER_CTX_free(ctx);
                outFile.close();
                return std::make_pair("Error", false);
            }
            outFile.write(reinterpret_cast<char*>(outBuffer), outLen);
            outStream.write(reinterpret_cast<char*>(outBuffer), outLen);
        }

        if (!EVP_DecryptFinal_ex(ctx, outBuffer, &outLen))
        {
            EVP_CIPHER_CTX_free(ctx);
            outFile.close();
            return std::make_pair("Error", false);
        }
        outFile.write(reinterpret_cast<char*>(outBuffer), outLen);
        outStream.write(reinterpret_cast<char*>(outBuffer), outLen);

        EVP_CIPHER_CTX_free(ctx);

        outFile.close();

        return std::make_pair(outStream.str(), true);
    }



    std::pair<std::string, bool> AESDecryptFile(const std::string& inputFile, const std::string& outputFile, const unsigned char* key)
    {
        const int bufferSize = 4096;
        unsigned char iv[AES_BLOCK_SIZE];
        unsigned char inBuffer[bufferSize + AES_BLOCK_SIZE];
        unsigned char outBuffer[bufferSize + AES_BLOCK_SIZE];
        std::ifstream inFile(inputFile, std::ios::binary);
        std::ofstream outFile(outputFile, std::ios::binary);
        std::ostringstream outStream;

        if (!inFile || !outFile)
        {
            std::cerr << "Error File.\n";
            return std::make_pair("Error opening File.", false);
        }

        inFile.read(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);

        EVP_CIPHER_CTX* ctx;
        ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);

        int bytesRead, plainLen, outLen;
        while ((bytesRead = inFile.read(reinterpret_cast<char*>(inBuffer), bufferSize + AES_BLOCK_SIZE).gcount()) > 0)
        {
            if (!EVP_DecryptUpdate(ctx, outBuffer, &outLen, inBuffer, bytesRead))
            {
                EVP_CIPHER_CTX_free(ctx);
                inFile.close();
                outFile.close();
                return std::make_pair("Error", false);
            }
            outFile.write(reinterpret_cast<char*>(outBuffer), outLen);
            outStream.write(reinterpret_cast<char*>(outBuffer), outLen);
        }

        if (!EVP_DecryptFinal_ex(ctx, outBuffer, &outLen))
        {
            EVP_CIPHER_CTX_free(ctx);
            inFile.close();
            outFile.close();
            return std::make_pair("Error", false);
        }
        outFile.write(reinterpret_cast<char*>(outBuffer), outLen);
        outStream.write(reinterpret_cast<char*>(outBuffer), outLen);

        EVP_CIPHER_CTX_free(ctx);

        inFile.close();
        outFile.close();

        return std::make_pair(outStream.str(), true);
    }


    std::pair<std::string, bool> AESEncryptAndHashFile(const std::string& inputFile, const std::string& outputFile, const std::string& hashFile, const unsigned char* key)
    {

        // Compute and write the SHA-512 hash of the encrypted file
        std::string FileContent = readFileContent(inputFile);
        std::string hash = hashSHA512::computeSHA512(reinterpret_cast<const unsigned char*>(FileContent.c_str()), FileContent.size());
        AESEncryptData(hash, hashFile, key);


        return AESEncryptFile(inputFile, outputFile, key);
    }

    std::pair<std::string, bool> AESEncryptAndHashData(const std::string& inputData, const std::string& outputFile, const std::string& hashFile, const unsigned char* key)
    {

        std::string hash = hashSHA512::computeSHA512(reinterpret_cast<const unsigned char*>(inputData.c_str()), inputData.size());
        AESEncryptData(hash, hashFile, key);


        return AESEncryptData(inputData, outputFile, key);
    }


    std::pair<std::string, bool> AESDecryptAndHashFile(const std::string& inputFile, const std::string& outputFile, const std::string& hashEncryptedFile, const std::string& hashDecryptedFile, const unsigned char* key)
    {
        AESDecryptFile(hashEncryptedFile, hashDecryptedFile, key);

        // Read the stored hash from the hash file
        std::ifstream hashFileR(hashDecryptedFile, std::ios::binary);
        std::string storedHash((std::istreambuf_iterator<char>(hashFileR)), {});
        hashFileR.close();

        std::pair<std::string, bool> decrypt;

        decrypt = AESDecryptFile(inputFile, outputFile, key);

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

        return decrypt;
    }

    std::pair<std::string, bool> AESDecryptAndHashData(const std::string& inputData, const std::string& outputFile, const std::string& hashEncryptedFile, const std::string& hashDecryptedFile, const unsigned char* key)
    {
        AESDecryptFile(hashEncryptedFile, hashDecryptedFile, key);

        // Read the stored hash from the hash file
        std::ifstream hashFileR(hashDecryptedFile, std::ios::binary);
        std::string storedHash((std::istreambuf_iterator<char>(hashFileR)), {});
        hashFileR.close();

        std::pair<std::string, bool> decrypt;

        decrypt = AESDecryptData(inputData, outputFile, key);

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

        return decrypt;
    }

}