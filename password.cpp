#include "password.h"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdexcept>
#include <cstring>
#include <fstream>

Password::Password(int itcount):
    iterationCount(itcount)
{
    // generate salt and iv
    RAND_bytes(saltBytes, SALT_LENGTH);
    RAND_bytes(iv, IV_LENGTH);
}

Password::Password(int itcount, unsigned char *key_, unsigned char *salt):
    iterationCount(itcount)
{
    std::memcpy(key, key_, KEY_LENGTH);
    std::memcpy(saltBytes, salt, SALT_LENGTH);
    RAND_bytes(iv, IV_LENGTH);
}

void Password::deriveKey(const char *plaintext, int plaintext_len) {
    // Derive key using PBKDF2
    PKCS5_PBKDF2_HMAC_SHA1(plaintext, plaintext_len,
                           saltBytes, SALT_LENGTH,
                           iterationCount, KEY_LENGTH, key);
}

void Password::deriveKey(const char *plaintext, int plaintext_len, unsigned char *out) {
    PKCS5_PBKDF2_HMAC_SHA1(plaintext, plaintext_len,
                           saltBytes, SALT_LENGTH,
                           iterationCount, KEY_LENGTH, out);
}

void Password::encrypt(const char *plaintext, int plaintext_len) {
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    const int blockSize = EVP_CIPHER_block_size(cipher);

    deriveKey(plaintext, plaintext_len);

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
    auto *decryptedPassword = (unsigned char*)malloc(strlen(reinterpret_cast<const char *>(ciphertext)));
    int plaintextLen = 0;

    EVP_DecryptUpdate(ctx, decryptedPassword, &plaintextLen,
                      ciphertext, encryptedPassword.size());

    int finalPlaintextLength = 0;
    EVP_DecryptFinal_ex(ctx, decryptedPassword + plaintextLen, &finalPlaintextLength);
    plaintextLen += finalPlaintextLength;
    EVP_CIPHER_CTX_free(ctx);

    return {reinterpret_cast<const char *>(decryptedPassword)};
}

std::string Password::getEncryptedPassword() {
    return this->encryptedPassword;
}

void Password::storeKey(const std::string& fname) {
    std::ofstream ofs(fname, std::ios::binary);
    if (!ofs)
        throw std::runtime_error("Error writing file!");
    ofs.write("PW", 2); // The header field to identify the file is `PW` in ASCII
    ofs.write(reinterpret_cast<const char *>(&key), KEY_LENGTH);
    ofs.write(reinterpret_cast<const char *>(&saltBytes), SALT_LENGTH);
    ofs.close();
}

void Password::readKey(const std::string& fname) {
    std::ifstream ifs(fname, std::ios::binary|std::ios::ate);
    ifs.seekg(0);

    char mg_str[2];
    ifs.read(mg_str, 2);
    ifs.read(reinterpret_cast<char *>(&key), KEY_LENGTH);
    ifs.read(reinterpret_cast<char *>(&saltBytes), SALT_LENGTH);

    ifs.close();
}

bool Password::validatePassword(const std::string &input) {
    unsigned char inputKey[KEY_LENGTH];
    deriveKey(input.c_str(), input.size(), inputKey);
    return std::equal(std::begin(inputKey), std::end(inputKey), std::begin(key));
}

unsigned char *Password::getKey() {
    return key;
}

unsigned char *Password::getSalt() {
    return saltBytes;
}
