#ifndef CPP_PASSMAN_VAULT_H
#define CPP_PASSMAN_VAULT_H
#include <string>

class Vault {
public:
    Vault();
private:
    unsigned id;
    unsigned user_id;
    unsigned short security_level;
    std::string name;
};

#endif //CPP_PASSMAN_VAULT_H
