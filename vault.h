#ifndef CPP_PASSMAN_VAULT_H
#define CPP_PASSMAN_VAULT_H
#include <string>
#include "password.h"

class Vault {
public:
    Vault();
    Vault(unsigned int id_, unsigned int user_id_);
    Vault(unsigned int user_id_, std::string name_, unsigned short sl, const std::string& pass);
    bool validateMasterPassword(const std::string& pass);
    unsigned int id;
    void writeToBin();
    void readFromBin();
    Password createNewPassword(const std::string& password_plaintext);
    friend std::ostream& operator<<(std::ostream& os, const Vault& v);
    unsigned int getAccountCount();

    std::string name;
    unsigned short security_level;

private:
    int iteration_count;
    Password masterPassword;
    std::string masterPasswordPlaintext;
    std::string dir_path;
};

#endif //CPP_PASSMAN_VAULT_H
