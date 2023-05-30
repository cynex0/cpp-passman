#include "app.h"
#include <iostream>
#include <vector>
#include <filesystem>
namespace fs = std::filesystem;
#include "fort.hpp"


App::App(): isRunning(true), state(MenuState::user_login) {
    if (!fs::exists("data"))
        fs::create_directory("data");
}

char App::getUserChoice() {
    char choice;
    std::cin >> choice;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Ignore remaining characters in input buffer
    return choice;
}

template <typename T> unsigned int App::selectFromVector(const std::vector<T> &v) {
    unsigned int N;
    std::string numbuf;

    for (;;){ // A WILD WALRUS APPEARS!
        std::cout << "Enter ID [[N]]: ";
        std::cin >> numbuf;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(),
                        '\n'); // Ignore remaining characters in input buffer
        N = strtoul(numbuf.c_str(), nullptr, 10);
        if (N < v.size()) {
            return N;
        } else {
            std::cout << "Invalid ID. Please try again." << std::endl;
        }
    }
}

std::vector<User> App::readUsers() {
    std::vector<User> users;
    for (const auto &u_entry: fs::directory_iterator("data")) {
        if (!u_entry.is_directory()) continue;
        unsigned int user_id = std::stoul(u_entry.path().filename().string());
        User user(user_id);
        users.emplace_back(user);
    }
    return users;
}

std::vector<Vault> App::readVaults(unsigned int uid) {
    std::vector<Vault> vaults;
    for (const auto &v_entry: fs::directory_iterator("data/" + std::to_string(uid))) {
        if (!v_entry.is_directory()) continue;
        unsigned int vault_id = std::stoul(v_entry.path().filename().string());
        Vault vault(vault_id, uid);
        vaults.emplace_back(vault);
    }
    return vaults;
}

std::vector<Account> App::readAccounts(unsigned int uid, unsigned int vid) {
    std::vector<Account> accounts;
    for (const auto &a_entry: fs::directory_iterator(
            "data/" + std::to_string(uid) + "/" + std::to_string(vid))) {
        if (a_entry.path().extension().string() != ".acc") continue;
        unsigned int acc_id = std::stoul(a_entry.path().stem().string());
        Account acc(acc_id, uid, vid);
        accounts.emplace_back(acc);
    }
    return accounts;
}

void App::printUserTable(std::vector<User> &users) {
    ft_table_t *table;
    table = ft_create_table();
    // header
    ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
    ft_write_ln(table, "[[N]]", "Name", "Last accessed", "Created on", "Vaults");

    for (auto it = users.begin(); it != users.end(); ++it) {
        auto index = std::distance(users.begin(), it);
        ft_write_ln(table, std::to_string(index).c_str(), it->name.c_str(), it->getTimeLastAccessed(),
                    it->getTimeCreated(), std::to_string(it->getVaultCount()).c_str());
    }

    printf("%s\n", ft_to_string(table));
    ft_destroy_table(table);
}

void App::printVaultTable(std::vector<Vault> &vaults) {
    ft_table_t *table;
    table = ft_create_table();
    // header
    ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
    ft_write_ln(table, "[[N]]", "Name", "Security level", "Stored Accounts");

    for (auto it = vaults.begin(); it != vaults.end(); ++it) {
        auto index = std::distance(vaults.begin(), it);
        ft_write_ln(table, std::to_string(index).c_str(), it->name.c_str(), std::to_string(it->security_level).c_str(),
                    std::to_string(it->getAccountCount()).c_str());
    }

    printf("%s\n", ft_to_string(table));
    ft_destroy_table(table);
}

void App::printAccountTable(std::vector<Account> &accounts, bool show_passwords, const std::string& master_password) {
    ft_table_t *table;
    table = ft_create_table();
    // header
    ft_set_cell_prop(table, 0, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
    ft_write_ln(table, "Name", "Login", "Password");

    for (auto it = accounts.begin(); it != accounts.end(); ++it) {
        std::string password = "********";
        if (show_passwords)
            password = it->getDecryptedPassword(master_password.c_str(), master_password.size());

        ft_write_ln(table, it->name.c_str(), it->login.c_str(), password.c_str());
    }

    printf("%s\n", ft_to_string(table));
    ft_destroy_table(table);
}

void App::printMenu() {
    std::vector<User> users;
    std::vector<Vault> vaults;
    std::vector<Account> accounts;
    bool show_passwords = false;

    while(isRunning) {
        switch (state) {
            case MenuState::user_login: {
                // read all stored users
                users = readUsers();
                printUserTable(users);

                if (!users.empty())
                    std::cout << "E: Select User" << std::endl;
                std::cout << "N: New User" << std::endl;
                std::cout << "Q: Quit" << std::endl;

                for (;;){ // WALRUS!
                    char choice = getUserChoice();
                    if ((choice == 'E' || choice == 'e') && !users.empty()) {
                        unsigned int current_user_n = selectFromVector(users);
                        current_user = users[current_user_n];
                        current_user.updateTimeLastAccessed();
                        state = MenuState::vault_list;
                        break; // for

                    } else if (choice == 'N' || choice == 'n') {
                        std::string new_user_name;
                        std::cout << "Enter user name: ";
                        std::getline(std::cin, new_user_name);
                        User new_user(new_user_name);
                        new_user.writeToBin();
                        users.emplace_back(new_user);
                        current_user = new_user;
                        current_user.updateTimeLastAccessed();
                        state = MenuState::vault_list;
                        break; // for

                    } else if (choice == 'Q' || choice == 'q') {
                        return; // Quit the program

                    } else {
                        std::cout << "Invalid choice. Please try again." << std::endl;
                    }
                }
                break; // case
            }

            case MenuState::vault_list: {
                std::cout << "Welcome, " << current_user.name << "!";

                // read all vaults belonging to current user
                vaults = readVaults(current_user.id);
                printVaultTable(vaults);

                if (!vaults.empty())
                    std::cout << "E: Select Vault" << std::endl;
                std::cout << "N: New Vault" << std::endl;
                std::cout << "R: Return to user select" << std::endl;
                std::cout << "Q: Quit" << std::endl;

                // vaults option selector
                for (;;){ // WALRUS!
                    char choice = getUserChoice();
                    if ((choice == 'E' || choice == 'e') && !vaults.empty()) {
                        unsigned int current_vault_n = selectFromVector(vaults);

                        std::string password_input;
                        std::cout << "Enter vault password: ";
                        std::getline(std::cin, password_input);
                        if (vaults[current_vault_n].validateMasterPassword(password_input)) {
                            current_vault = vaults[current_vault_n];
                            state = MenuState::account_list;
                            break; // for
                        } else {
                            std::cout << "Invalid password! Please try again! ";
                        }
                    } else if (choice == 'N' || choice == 'n') {
                        std::string new_vault_name;
                        std::cout << "Enter vault name: ";
                        std::getline(std::cin, new_vault_name);

                        std::string new_password;
                        std::cout << "Enter desired master password: ";
                        std::getline(std::cin, new_password);

                        Vault new_vault(current_user.id, new_vault_name, 0, new_password);
                        new_vault.writeToBin();
                        vaults.emplace_back(new_vault);

                        current_vault = new_vault;
                        state = MenuState::account_list;
                        break; // for

                    } else if (choice == 'R' || choice == 'r') {
                        state = MenuState::user_login; // Return to the previous stage
                        break; // for

                    } else if (choice == 'Q' || choice == 'q') {
                        return; // Quit the program

                    } else {
                        std::cout << "Invalid choice. Please try again." << std::endl;
                    }
                } // for
                break; // case
            }

            case MenuState::account_list: {
                std::cout << "Entered vault \"" << current_vault.name << "\"\n";
                accounts = readAccounts(current_user.id, current_vault.id);

                if(!show_passwords)
                    printAccountTable(accounts, show_passwords, "");

                if (!accounts.empty() && !show_passwords)
                        std::cout << "S: Show Passwords" << std::endl;

                if (!accounts.empty() && show_passwords)
                    std::cout << "H: Hide Passwords" << std::endl;

                std::cout << "N: New Account" << std::endl;
                std::cout << "R: Return to user select" << std::endl;
                std::cout << "Q: Quit" << std::endl;

                // vaults option selector
                for (;;) { // WALRUS!
                    char choice = getUserChoice();
                    if ((choice == 'S' || choice == 's') && !accounts.empty() && !show_passwords) {
                        std::cout << "Please repeat master password: ";
                        std::string password_input;
                        std::getline(std::cin, password_input);
                        if (current_vault.validateMasterPassword(password_input)) {
                            show_passwords = true;
                            printAccountTable(accounts, show_passwords, password_input);
                            break; // for
                        } else std::cout << "Invalid password! Please try again!\n";
                    } else if ((choice == 'H' || choice == 'h') && !accounts.empty() && show_passwords) {
                        show_passwords = false;
                        break;
                    } else if (choice == 'N' || choice == 'n') {
                        std::string new_name;
                        std::cout << "Enter account name: ";
                        std::getline(std::cin, new_name);

                        std::string new_login;
                        std::cout << "Enter account login: ";
                        std::getline(std::cin, new_login);

                        std::string new_password;
                        std::cout << "Enter account password: ";
                        std::getline(std::cin, new_password);

                        Account new_account(current_user.id, current_vault.id, new_name, new_login, current_vault.createNewPassword(new_password));
                        new_account.writeToBin();
                        accounts.emplace_back(new_account);
                        break; // for

                    } else if (choice == 'R' || choice == 'r') {
                        state = MenuState::user_login; // Return to the previous stage
                        break; // for

                    } else if (choice == 'Q' || choice == 'q') {
                        return; // Quit the program

                    } else {
                        std::cout << "Invalid choice. Please try again." << std::endl;
                    }
                } // for

                break; // case
            }
        }
    }
}
