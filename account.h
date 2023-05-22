#ifndef CPP_PASSMAN_ACCOUNT_H
#define CPP_PASSMAN_ACCOUNT_H
#include <string>

class Account {
public:
    Account();
    std::string name;
private:
    unsigned id;
    std::string login;
    std::string password_hash;
};

#endif //CPP_PASSMAN_ACCOUNT_H
