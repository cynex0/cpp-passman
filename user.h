#ifndef CPP_PASSMAN_USER_H
#define CPP_PASSMAN_USER_H
#include <string>
#include <ctime>

class User {
public:
    User();
    std::string name;
    std::string login;
    std::time_t last_accessed;

private:
    unsigned id;
    std::string master_pswrd_hash; // TODO: password hash class
};

#endif //CPP_PASSMAN_USER_H
