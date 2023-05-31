#ifndef CPP_PASSMAN_ACCOUNT_H
#define CPP_PASSMAN_ACCOUNT_H
#include <string>
#include "password.h"

class Account {
public:
    Account(unsigned int id_, unsigned int user_id_, unsigned int vault_id_);
    Account(unsigned int user_id_, unsigned int vault_id_, std::string name_, std::string login_, std::string password_);
    Account(unsigned int user_id_, unsigned int vault_id_, std::string name_, std::string login_, Password password_);
    std::string name;
    std::string login;
    unsigned int id;
    void writeToBin();
    void readFromBin();
    void writeToBin_plaintext();
    void readFromBin_plaintext();

    std::string getPassword();

    std::string getDecryptedPassword(const char *master, size_t master_len);
    friend std::ostream& operator<<(std::ostream& os, Account& acc);
private:
    Password password;
    std::string password_plaintext;

    std::string file_path;
};

#endif //CPP_PASSMAN_ACCOUNT_H
