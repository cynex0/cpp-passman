#include <iostream>
#include "password.h"
#include "vault.h"
#include "account.h"
#include "user.h"
#include "app.h"
#include <filesystem>
namespace fs = std::filesystem;

void writeTest() {
    std::string masterPassword = "Super_Ultra-Mega/seCrEtPaSsWorD!";
    std::string userPassword = "secretPassword";
    App app;
    for (int i{0}; i < 2; i++) {
        User user("User " + std::to_string(i));
        user.writeToBin();

        for (int j{0}; j < 3; j++) {
            Vault vault(user.id, "My Vault " + std::to_string(i)+std::to_string(j), 10+i, masterPassword);
            vault.writeToBin();

            for (int k{0}; k < 2; k++) {
                Account acc(user.id, vault.id, "Important Password", "admin"+std::to_string(i)+std::to_string(j)+std::to_string(k), vault.createNewPassword(userPassword));
                acc.writeToBin();
            }
        }
    }
}

void readTest() {
    std::string masterPassword = "Super_Ultra-Mega/seCrEtPaSsWorD!";

    std::vector<User> users;
    std::vector<Vault> vaults;
    std::vector<Account> accounts;

    for (const auto& u_entry : fs::directory_iterator("data")) {
        if (!u_entry.is_directory()) continue;
        unsigned int user_id = std::stoul(u_entry.path().filename().string());
        User user(user_id);
        users.emplace_back(user);
        std::cout << user << '\n';

        for (const auto &v_entry: fs::directory_iterator("data/" + std::to_string(user_id))) {
            if (!v_entry.is_directory()) continue;
            unsigned int vault_id = std::stoul(v_entry.path().filename().string());
            Vault vault(vault_id, user_id);
            vaults.emplace_back(vault);
            std::cout << '\t' << vault << '\n';

            for (const auto &a_entry: fs::directory_iterator(
                    "data/" + std::to_string(user_id) + "/" + std::to_string(vault_id))) {
                if (a_entry.path().extension().string() != ".acc") continue;
                unsigned int acc_id = std::stoul(a_entry.path().stem().string());
                Account acc(acc_id, user_id, vault_id);
                accounts.emplace_back(acc);
                std::cout << "\t\t" << acc << acc.getDecryptedPassword(masterPassword.c_str(), masterPassword.size()) << '\n';
            }
        }
    }
}

int main() {
//    writeTest();
//    readTest();

    App app;
    app.run();
    std::cout << "Goodbye!";
    return 0;
}
