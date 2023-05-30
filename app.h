#ifndef CPP_PASSMAN_APP_H
#define CPP_PASSMAN_APP_H

#include "user.h"
#include "vault.h"
#include "account.h"

enum class MenuState { user_login, vault_list, account_list };

class App {
public:
    App();
    void printMenu();

    bool isRunning;
private:
    char getUserChoice();
    template<typename T> unsigned int selectFromVector(const std::vector<T> &v);
    void printUserTable(std::vector<User> &users);
    void printVaultTable(std::vector<Vault> &vaults);

    MenuState state;
    User current_user;
    Vault current_vault;

    std::vector<User> readUsers();
    std::vector<Vault> readVaults(unsigned int uid);

    std::vector<Account> readAccounts(unsigned int uid, unsigned int vid);
    void printAccountTable(std::vector<Account> &accounts, bool show_passwords, const std::string &master_password);
};

#endif //CPP_PASSMAN_APP_H
