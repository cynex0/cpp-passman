#include "password.h"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdexcept>
#include <cstring>
#include <fstream>
#include <iostream>

Password::Password(int itcount):
    ciphertext_len(0),
    iterationCount(itcount)
{
    // generate salt and iv
    RAND_bytes(saltBytes, SALT_LENGTH);
    RAND_bytes(iv, IV_LENGTH);
}

Password::Password(int itcount, unsigned char *key_, unsigned char *salt):
    ciphertext_len(0),
    iterationCount(itcount)
{
    std::memcpy(key, key_, KEY_LENGTH);
    std::memcpy(saltBytes, salt, SALT_LENGTH);
    RAND_bytes(iv, IV_LENGTH);
}

Password::Password(int itcount, unsigned char *ciphertext_, int ciphertext_len_, unsigned char *salt, unsigned char *iv_):
    ciphertext(ciphertext_),
    ciphertext_len(ciphertext_len_),
    iterationCount(itcount)
{
    std::memcpy(saltBytes, salt, SALT_LENGTH);
    std::memcpy(iv, iv_, IV_LENGTH);
}

void Password::deriveKey(const char *plaintext, int plaintext_len) {
    if (iterationCount == 0) return;
    PKCS5_PBKDF2_HMAC_SHA1(plaintext, plaintext_len,
                           saltBytes, SALT_LENGTH,
                           iterationCount, KEY_LENGTH, key);
}

void Password::deriveKey(const char *plaintext, int plaintext_len, unsigned char *out) {
    if (iterationCount == 0) return;
    PKCS5_PBKDF2_HMAC_SHA1(plaintext, plaintext_len,
                           saltBytes, SALT_LENGTH,
                           iterationCount, KEY_LENGTH, out);
}

void Password::encrypt(const char *plaintext, int plaintext_len) {
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    const int blockSize = EVP_CIPHER_block_size(cipher);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);

    // Calculate the maximum ciphertext length
    int maxCiphertextLength = plaintext_len + blockSize;
    ciphertext = new unsigned char[maxCiphertextLength];

    int ciphertextLength = 0;
    EVP_EncryptUpdate(ctx, ciphertext, &ciphertextLength, (const unsigned char*)plaintext, plaintext_len);
    ciphertext_len = ciphertextLength;

    int finalCiphertextLength = 0;
    EVP_EncryptFinal_ex(ctx, ciphertext + ciphertextLength, &finalCiphertextLength);

    finalCiphertextLength += ciphertextLength;
    EVP_CIPHER_CTX_free(ctx);
    this->ciphertext_len = finalCiphertextLength;
}

std::string Password::decrypt() const{
    int len;
    int plaintext_len;

    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);
    auto plaintext_buffer = (unsigned char*)malloc(ciphertext_len);

    EVP_DecryptUpdate(ctx, plaintext_buffer, &len, ciphertext, ciphertext_len);

    plaintext_len = len;

    EVP_DecryptFinal_ex(ctx, plaintext_buffer + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    std::string decrypted_string(reinterpret_cast<const char*>(plaintext_buffer), plaintext_len);
    free(plaintext_buffer);
    return decrypted_string;
}

bool Password::validatePassword(const std::string &input) {
    unsigned char inputKey[KEY_LENGTH];
    deriveKey(input.c_str(), input.size(), inputKey);
    return std::equal(std::begin(inputKey), std::end(inputKey), std::begin(key));
}
