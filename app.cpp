#include "app.h"
#include <iostream>
#include <algorithm>
#include <vector>
#include <cstdlib>
#include <filesystem>
namespace fs = std::filesystem;
#include "fort.hpp"

#if defined WIN32 || defined WIN64
#define CLEAR_COMMAND "cls"
#else// Assume POSIX
#define CLEAR_COMMAND "clear"
#endif

/**
 * The constructor for the App class.
 * Initializes the isRunning flag and sets the initial state to MenuState::user_login.
 * Creates a "data" directory if it doesn't exist.
 */
App::App(): isRunning(true), state(MenuState::user_login) {
    if (!fs::exists("data"))
        fs::create_directory("data");
}

/**
 * Reads a single character input from the user.
 * Ignores any remaining characters in the input buffer.
 *
 * @return The character entered by the user.
 */
char App::getUserChoice() {
    char choice;
    std::cin >> choice;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Ignore remaining characters in input buffer
    return choice;
}

/**
 * Allows the user to select an item from a vector by entering its index.
 *
 * @tparam T The type of elements in the vector.
 * @param v The vector from which to select an item.
 * @return The index of the selected item.
 */
template <typename T> unsigned int App::selectFromVector(const std::vector<T> v) {
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

/**
 * Reads and returns a vector of User objects from the "data" directory.
 *
 * @return The vector of User objects.
 */
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

/**
 * Reads and returns a vector of Vault objects for a given user ID.
 *
 * @param uid The ID of the user.
 * @return The vector of Vault objects.
 */
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

/**
 * Reads and returns a vector of Account objects for a given user ID and vault ID.
 *
 * @param uid The ID of the user.
 * @param vid The ID of the vault.
 * @return The vector of Account objects.
 */
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

/**
 * Prints a formatted table displaying information about each user.
 *
 * @param users A reference to a vector of User objects.
 *
 * The function prints a table with the following columns:
 *   - Index: The numeric index of the user.
 *   - Name: The name of the user.
 *   - Last accessed: The time when the user was last accessed.
 *   - Created on: The time when the user was created.
 *   - Vaults: The number of vaults associated with the user.
 */
void App::printUserTable(std::vector<User> &users) {
    fort::char_table table;
    // header
    table << fort::header << "[[N]]" << "Name" << "Last accessed" << "Created on" << "Vaults" << fort::endr;

    for (auto it = users.begin(); it != users.end(); ++it) {
        auto index = std::distance(users.begin(), it);
        table << index << it->name << it->getTimeLastAccessed() << it->getTimeCreated() << it->getVaultCount() << fort::endr;
    }
    std::cout << table.to_string();
}

/**
 * Prints a formatted table displaying information about each vault.
 *
 * @param vaults A reference to a vector of Vault objects.
 *
 * The function prints a table with the following columns:
 *   - Index: The numeric index of the vault.
 *   - Name: The name of the vault.
 *   - Security level: The security level of the vault.
 *   - Stored Accounts: The number of accounts stored in the vault.
 */
void App::printVaultTable(std::vector<Vault> &vaults) {
    fort::char_table table;
    // header
    table << fort::header << "[[N]]" << "Name" << "Security level" << "Stored Accounts" << fort::endr;

    for (auto it = vaults.begin(); it != vaults.end(); ++it) {
        auto index = std::distance(vaults.begin(), it);
        table << index << it->name << it->security_level << it->getAccountCount() << fort::endr;
    }
    std::cout << table.to_string();
}

/**
 * Prints a formatted table displaying information about each account.
 *
 * @param accounts         A reference to a vector of Account objects.
 * @param show_passwords   A boolean indicating whether to display the account passwords or mask them.
 * @param master_password  The master password used for decrypting the account passwords (required if show_passwords is true).
 *
 * The function prints a table with the following columns:
 *   - Name: The name of the account.
 *   - Login: The login username for the account.
 *   - Password: The password for the account. If show_passwords is true, the actual password is displayed.
 *               Otherwise, the password is masked with asterisks ("********").
 */
void App::printAccountTable(std::vector<Account> &accounts, bool show_passwords, const std::string& master_password) {
    fort::char_table table;
    table << fort::header << "Name" << "Login" << "Password" << fort::endr;
    for (auto acc : accounts){
        std::string password;
        if (show_passwords){
            password = acc.getDecryptedPassword(master_password.c_str(), master_password.size());
        }
        else password = "********";
        table << acc.name << acc.login << password << fort::endr;
    }
    std::cout << table.to_string() << std::endl;
}

/**
 * Displays a menu and handles user interaction based on the current state.
 *
 * The function presents different options and performs corresponding actions based on the current state.
 * It uses vectors to store User, Vault, and Account objects, as well as variables to track the state and display messages.
 *
 * The function consists of a loop that continues until the program is quit. Within the loop, the function uses a switch
 * statement to determine the appropriate actions based on the current state.
 *
 * The function supports the following states:
 *   - MenuState::user_login: Displays the user login menu, allowing users to select existing users, create new users,
 *                            sort users, delete users, or quit the program.
 *   - MenuState::vault_list: Displays the vault list menu for the currently selected user, allowing users to select existing
 *                            vaults, create new vaults, return to the user login menu, or quit the program.
 *   - MenuState::account_list: Displays the account list menu for the currently selected vault, allowing users to view
 *                              accounts (with or without passwords), create new accounts, return to the user login menu,
 *                              or quit the program.
 */
void App::run() {
    std::vector<User> users;
    std::vector<Vault> vaults;
    std::vector<Account> accounts;
    std::string message;
    bool show_passwords = false;

    while(isRunning) {
        switch (state) {
            case MenuState::user_login: {
                // read all stored users
                if (users.empty())
                    users = readUsers();
                printUserTable(users);
                std::cout << '[' << message << "]\n";
                message = "";

                if (!users.empty())
                    std::cout << "E: Select User" << std::endl;
                std::cout << "N: New User" << std::endl;
                std::cout << "O: Sort" << std::endl;
                std::cout << "D: Delete" << std::endl;
                std::cout << "Q: Quit" << std::endl;


                char choice = getUserChoice();
                if ((choice == 'E' || choice == 'e') && !users.empty()) {
                    unsigned int current_user_n = selectFromVector(users);
                    current_user = users[current_user_n];
                    current_user.updateTimeLastAccessed();

                    state = MenuState::vault_list;
                    message = "Welcome, " + current_user.name + "!";
                    break;

                } else if (choice == 'N' || choice == 'n') {
                    std::string new_user_name;
                    std::cout << "Enter user name: ";
                    std::getline(std::cin, new_user_name);

                    User new_user(new_user_name);
                    new_user.writeToBin();
                    users.emplace_back(new_user);

                    current_user = new_user;
                    current_user.updateTimeLastAccessed();

                    message = "Welcome, " + current_user.name + "!";
                    state = MenuState::vault_list;
                    break;

                } else if (choice == 'O' || choice == 'o') {
                    int sort_field = 0;
                    std::cout << "Sort by:";
                    std::cout << "\t1: Name" << std::endl;
                    std::cout << "\t2: Last accessed" << std::endl;
                    std::cout << "\t3: Created on" << std::endl;
                    std::cin >> sort_field;

                    switch(sort_field){
                        case 1:
                            std::sort(users.begin(), users.end(),
                                      [](const User &u1, const User &u2){return u1.name < u2.name;});
                            break;
                        case 2:
                            std::sort(users.begin(), users.end(),
                                      [](const User &u1, const User &u2){return u1.time_last_accessed < u2.time_last_accessed;});
                            break;
                        case 3:
                            std::sort(users.begin(), users.end(),
                                      [](const User &u1, const User &u2){return u1.time_created < u2.time_created;});
                            break;
                        default:
                            message = "Invalid sort field! Please try again!";
                    }

                } else if (choice == 'D' || choice == 'd') {
                    unsigned int delete_n = selectFromVector(users);
                    fs::remove_all("data/" + std::to_string(users[delete_n].id));
                    users.erase(users.begin()+delete_n);
                } else if (choice == 'Q' || choice == 'q') {
                    return; // Quit the program

                } else {
                    message = "Invalid choice. Please try again.";
                }

                break; // case
            }

            case MenuState::vault_list: {
                // read all vaults belonging to current user
                if (vaults.empty())
                    vaults = readVaults(current_user.id);
                printVaultTable(vaults);
                std::cout << '[' << message << "]\n";
                message = "";

                if (!vaults.empty())
                    std::cout << "E: Select Vault" << std::endl;
                std::cout << "N: New Vault" << std::endl;
                std::cout << "R: Return to user select" << std::endl;
                std::cout << "Q: Quit" << std::endl;

                // vaults option selector
                char choice = getUserChoice();
                if ((choice == 'E' || choice == 'e') && !vaults.empty()) {
                    unsigned int current_vault_n = selectFromVector(vaults);

                    std::string password_input;
                    std::cout << "Enter vault password: ";
                    std::getline(std::cin, password_input);
                    if (vaults[current_vault_n].validateMasterPassword(password_input)) {
                        current_vault = vaults[current_vault_n];
                        state = MenuState::account_list;
                        message = "Entered vault \"" + current_vault.name + "\"";
                        break;
                    } else {
                        message = "Invalid password! Please try again!";
                    }
                } else if (choice == 'N' || choice == 'n') {
                    std::string new_vault_name;
                    std::cout << "Enter vault name: ";
                    std::getline(std::cin, new_vault_name);

                    std::string new_password;
                    std::cout << "Enter desired master password: ";
                    std::getline(std::cin, new_password);

                    unsigned short sl;
                    std::string sl_buf;
                    std::cout << "Enter desired security level\n(0-20, 10 recommended):";
                    std::getline(std::cin, sl_buf);
                    sl = stoul(sl_buf);
                    if (sl > 20) {
                        message = "Invalid security level! Please try again!";
                        break;
                    }

                    Vault new_vault(current_user.id, new_vault_name, sl, new_password);
                    new_vault.writeToBin();
                    vaults.emplace_back(new_vault);

                    current_vault = new_vault;
                    state = MenuState::account_list;
                    message = "Entered vault \"" + current_vault.name + "\"";
                    break;

                } else if (choice == 'R' || choice == 'r') {
                    state = MenuState::user_login; // Return to the previous stage
                    users = readUsers();
                    break;

                } else if (choice == 'Q' || choice == 'q') {
                    return; // Quit the program

                } else {
                    message = "Invalid choice. Please try again.";
                }
                break; // case
            }

            case MenuState::account_list: {
                accounts = readAccounts(current_user.id, current_vault.id);

                if(!show_passwords)
                    printAccountTable(accounts, show_passwords, "");
                std::cout << '[' << message << "]\n";
                message = "";

                if (!accounts.empty() && !show_passwords)
                    std::cout << "S: Show Passwords" << std::endl;

                if (!accounts.empty() && show_passwords)
                    std::cout << "H: Hide Passwords" << std::endl;

                std::cout << "N: New Account" << std::endl;
                std::cout << "R: Return to user select" << std::endl;
                std::cout << "Q: Quit" << std::endl;

                // vaults option selector
                char choice = getUserChoice();
                if ((choice == 'S' || choice == 's') && !accounts.empty() && !show_passwords) {
                    std::cout << "Please repeat master password: ";
                    std::string password_input;
                    std::getline(std::cin, password_input);
                    if (current_vault.validateMasterPassword(password_input)) {
                        show_passwords = true;
                        printAccountTable(accounts, show_passwords, password_input);
                        break;
                    } else message = "Invalid password! Please try again!";
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

                    Account new_account(current_user.id, current_vault.id, new_name,
                                        new_login, current_vault.createNewPassword(new_password));
                    new_account.writeToBin();
                    accounts.emplace_back(new_account);
                    break;

                } else if (choice == 'R' || choice == 'r') {
                    state = MenuState::user_login; // Return to the previous stage
                    users = readUsers();
                    break;

                } else if (choice == 'Q' || choice == 'q') {
                    return; // Quit the program

                } else {
                    std::cout << "Invalid choice. Please try again." << std::endl;
                }

                break; // case
            }
        }
    }
}

