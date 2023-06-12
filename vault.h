#ifndef CPP_PASSMAN_VAULT_H
#define CPP_PASSMAN_VAULT_H
#include <string>

class Vault {
public:
    Vault();
    Vault(unsigned int id_, unsigned int user_id_);
    Vault(unsigned int user_id_, std::string name_, unsigned short sl, const std::string& pass);
    bool validateMasterPassword(const std::string& pass);
    unsigned int id;
    void writeToBin();
    void readFromBin();
    friend std::ostream& operator<<(std::ostream& os, const Vault& v);
    unsigned int getAccountCount();

    std::string name;
    unsigned short security_level;

private:
    int iteration_count;
    std::string masterPasswordPlaintext;
    std::string dir_path;

    static const uint8_t KEY_LENGTH = 32;  // 256 bits
    static const uint8_t IV_LENGTH = 16;   // 128 bits
    static const uint8_t SALT_LENGTH = 8;  // 64 bits
    unsigned char key[KEY_LENGTH];
    unsigned char saltBytes[SALT_LENGTH];
    unsigned char iv[IV_LENGTH];

    void deriveKey(const char *plaintext, size_t plaintext_len, unsigned char* out);
};

#endif //CPP_PASSMAN_VAULT_H
