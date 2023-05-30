#ifndef CPP_PASSMAN_USER_H
#define CPP_PASSMAN_USER_H
#include <string>
#include <ctime>
#include <vector>

class User {
public:
    User();
    User(const std::string& name_);
    User(unsigned int id_);
    unsigned id;
    std::string name;
    std::time_t time_created;
    std::time_t time_last_accessed;

    void writeToBin();
    void readFromBin();
    void updateTimeLastAccessed();
    unsigned int getVaultCount();
    char* getTimeLastAccessed();
    char* getTimeCreated();

    friend std::ostream& operator<<(std::ostream& os, const User& user);
private:
    std::string file_path;
};

#endif //CPP_PASSMAN_USER_H
