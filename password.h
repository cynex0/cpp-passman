#ifndef CPP_PASSMAN_PASSWORD_H
#define CPP_PASSMAN_PASSWORD_H

#include <string>
#include <vector>

class Password {
public:
    Password(int iterations = DEFAULT_ITERATION_COUNT);
    void encrypt(const char *plaintext, int plaintext_len);
    std::string getEncryptedPassword();
    std::string decrypt();

private:
    static const int KEY_LENGTH = 32;  // 256 bits
    static const int IV_LENGTH = 16;   // 128 bits
    static const int SALT_LENGTH = 8;  // 64 bits
    static const int DEFAULT_ITERATION_COUNT = 10000;

    int iterationCount;
    unsigned char key[KEY_LENGTH];
    unsigned char saltBytes[SALT_LENGTH];
    unsigned char iv[IV_LENGTH];
    std::string encryptedPassword;
    unsigned char *ciphertext;
};

#endif //CPP_PASSMAN_PASSWORD_H
