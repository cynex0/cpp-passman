#ifndef CPP_PASSMAN_VAULT_H
#define CPP_PASSMAN_VAULT_H
#include <string>
#include "password.h"

class Vault {
public:
    Vault(unsigned int id_);
    Vault(std::string name_, unsigned short sl, const std::string& pass);
    bool enter(const std::string& pass);
    unsigned int id;
    void writeToBin();
    void readFromBin(unsigned int id_);

private:
    unsigned short security_level;
    int iteration_count;
    std::string name;
    Password masterPassword;
};

#endif //CPP_PASSMAN_VAULT_H
