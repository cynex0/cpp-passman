#include "password.h"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdexcept>
#include <iostream>
#include <cstring>

Password::Password(int iterations) :
    iterationCount(iterations),
    encryptedPassword("")
{
    // generate salt and iv
    RAND_bytes(saltBytes, SALT_LENGTH);
    RAND_bytes(iv, IV_LENGTH);
}

//void Password::encrypt(const std::string &password, const std::string &passphrase) {
//    // derive key from passphrase
//    unsigned char derivedKey[KEY_LENGTH];
//    PKCS5_PBKDF2_HMAC_SHA1(passphrase.c_str(), passphrase.length(),
//                           saltBytes, SALT_LENGTH,
//                           iterationCount, KEY_LENGTH, derivedKey);
//
//    // create and initialize context
//    EVP_CIPHER_CTX *ctx;
//    int len;
//    int ciphertext_len;
//
//    if(!(ctx = EVP_CIPHER_CTX_new()))
//        throw std::runtime_error("Error while encrypting password!");
//
//    // Initialise the encryption operation. 256-bit AES, 128-bit iv
//    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, derivedKey, iv))
//        throw std::runtime_error("Error while initializing encryption algorithm!");
//
//    // obtain encrypted password
//    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
//        throw std::runtime_error("Error while encrypting password!");
//
//    ciphertext_len = len;
//
//    // finalize encryption
//    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
//        throw std::runtime_error("Error while encrypting password!");
//
//    ciphertext_len += len;
//
//    // Clean up
//    EVP_CIPHER_CTX_free(ctx);
//}

void Password::encrypt(const char *plaintext, int plaintext_len) {
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    const int blockSize = EVP_CIPHER_block_size(cipher);

    // Derive key using PBKDF2
    PKCS5_PBKDF2_HMAC_SHA1(plaintext, plaintext_len,
                           saltBytes, SALT_LENGTH,
                           iterationCount, KEY_LENGTH, key);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);


    // Calculate the maximum ciphertext length
    int maxCiphertextLength = plaintext_len + blockSize;
    ciphertext = (unsigned char*)malloc(maxCiphertextLength);

    int ciphertextLength = 0;
    EVP_EncryptUpdate(ctx, ciphertext, &ciphertextLength, (const unsigned char*)plaintext, plaintext_len);

    int finalCiphertextLength = 0;
    EVP_EncryptFinal_ex(ctx, ciphertext + ciphertextLength, &finalCiphertextLength);

    ciphertextLength += finalCiphertextLength;
    EVP_CIPHER_CTX_free(ctx);

    this->encryptedPassword = std::string(reinterpret_cast<char*>(ciphertext));
}

std::string Password::decrypt() {
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);
    unsigned char *decryptedPassword = (unsigned char*)malloc(strlen(reinterpret_cast<const char *>(ciphertext)));
    int plaintextLen = 0;

    EVP_DecryptUpdate(ctx, decryptedPassword, &plaintextLen,
                      ciphertext, encryptedPassword.size());

    int finalPlaintextLength = 0;
    EVP_DecryptFinal_ex(ctx, decryptedPassword + plaintextLen, &finalPlaintextLength);
    plaintextLen += finalPlaintextLength;
    EVP_CIPHER_CTX_free(ctx);

    return std::string(reinterpret_cast<const char *>(decryptedPassword));
}

std::string Password::getEncryptedPassword() {
    return this->encryptedPassword;
}
