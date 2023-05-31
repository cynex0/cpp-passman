#ifndef CPP_PASSMAN_PASSWORD_H
#define CPP_PASSMAN_PASSWORD_H

#include <string>
#include <vector>

class Password {
public:
    Password(int itcount = DEFAULT_ITERATION_COUNT);
    Password(int itcount, unsigned char *key_, unsigned char *salt);
    Password(int itcount, unsigned char *ciphertext_, int ciphertext_len_, unsigned char *salt, unsigned char *iv_);
    void encrypt(const char *plaintext, size_t plaintext_len_);
    std::string decrypt() const;
    void deriveKey(const char *plaintext, size_t plaintext_len);
    void deriveKey(const char *plaintext, size_t plaintext_len, unsigned char* out);
    bool validatePassword(const std::string& input);
    static const uint8_t KEY_LENGTH = 32;  // 256 bits
    static const uint8_t IV_LENGTH = 16;   // 128 bits
    static const uint8_t SALT_LENGTH = 8;  // 64 bits

    static const int DEFAULT_ITERATION_COUNT = 10000;
    unsigned char key[KEY_LENGTH];
    unsigned char saltBytes[SALT_LENGTH];

    unsigned char iv[IV_LENGTH];
    unsigned char* ciphertext;
    int ciphertext_len;
    int iterationCount;
private:
};

#endif //CPP_PASSMAN_PASSWORD_H
