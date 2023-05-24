#ifndef CPP_PASSMAN_PASSWORD_H
#define CPP_PASSMAN_PASSWORD_H

#include <string>
#include <vector>

class Password {
public:
    Password(int itcount = DEFAULT_ITERATION_COUNT);
    Password(int itcount, unsigned char *key_, unsigned char *salt);
    void encrypt(const char *plaintext, int plaintext_len);
    void deriveKey(const char *plaintext, int plaintext_len);
    void deriveKey(const char *plaintext, int plaintext_len, unsigned char* out);
    std::string getEncryptedPassword();
    std::string decrypt();
    void storeKey(const std::string& fname);
    void readKey(const std::string& fname);
    bool validatePassword(const std::string& input);
    unsigned char* getKey();
    unsigned char* getSalt();
    static const uint8_t KEY_LENGTH = 32;  // 256 bits
    static const uint8_t IV_LENGTH = 16;   // 128 bits
    static const uint8_t SALT_LENGTH = 8;  // 64 bits
    static const int DEFAULT_ITERATION_COUNT = 10000;

private:
    int iterationCount;
    unsigned char key[KEY_LENGTH]{};
    unsigned char saltBytes[SALT_LENGTH]{};
    unsigned char iv[IV_LENGTH]{};
    std::string encryptedPassword;
    unsigned char *ciphertext{};
};

#endif //CPP_PASSMAN_PASSWORD_H
