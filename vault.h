#ifndef CPP_PASSMAN_VAULT_H
#define CPP_PASSMAN_VAULT_H
#include <string>

class Vault {
public:
    Vault();
    Vault(unsigned int id_, unsigned int user_id_);
    Vault(unsigned int user_id_, std::string name_, const std::string& pass);
    bool validateMasterPassword(const std::string& pass);
    unsigned int id;
    void writeToBin();
    void readFromBin();
    friend std::ostream& operator<<(std::ostream& os, const Vault& v);
    unsigned int getAccountCount();

    std::string name;

private:
    int iteration_count;
    std::string masterPasswordPlaintext;
    std::string dir_path;

    static const uint8_t KEY_LENGTH = 32;  // 256 bits
    static const uint8_t IV_LENGTH = 16;   // 128 bits
    static const uint8_t SALT_LENGTH = 8;  // 64 bits
    static const int DEFAULT_ITERATION_COUNT = 15000;

    unsigned char key[KEY_LENGTH];
    unsigned char saltBytes[SALT_LENGTH];

    void deriveKey(const char *plaintext, size_t plaintext_len, unsigned char* out);
};

#endif //CPP_PASSMAN_VAULT_H
