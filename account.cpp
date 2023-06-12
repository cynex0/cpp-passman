#include "account.h"

#include <utility>
#include <openssl/rand.h>
#include <fstream>
#include <iostream>

/**
 * @brief Constructor for the Account class.
 * Initializes an Account object with the provided ID, user ID, and vault ID.
 * Sets the file path for the account data and reads data from the binary file.
 *
 * @param id_ The ID of the account.
 * @param user_id_ The ID of the user to whom the account belongs.
 * @param vault_id_ The ID of the vault to which the account belongs.
 */
Account::Account(unsigned int id_, unsigned int user_id_, unsigned int vault_id_):
    name(), login(), id(id_)
{
    file_path = "data/" + std::to_string(user_id_) + "/" + std::to_string(vault_id_) + "/" +
            std::to_string(id_) + ".acc";
    readFromBin_plaintext();
}

/**
 * @brief Constructor for the Account class.
 * Initializes an Account object with the provided user ID, vault ID, name, login, and password.
 * The password is written in plaintext. This is a temporary function to replace encryption algorithms.
 * To be removed when encryption works.
 * Generates a unique ID for the account.
 * Sets the file path for the account data.
 *
 * @param user_id_ The ID of the user to whom the account belongs.
 * @param vault_id_ The ID of the vault to which the account belongs.
 * @param name_ The name of the account.
 * @param login_ The login information of the account.
 * @param password_ The password of the account.
 */
Account::Account(unsigned int user_id_, unsigned int vault_id_, std::string name_, std::string login_, std::string password_):
    name(std::move(name_)),
    login(std::move(login_)),
    id(0),
    password_plaintext(std::move(password_))
{
    RAND_bytes(reinterpret_cast<unsigned char*>(&id), sizeof(id));
    file_path = "data/" + std::to_string(user_id_) + "/" + std::to_string(vault_id_) + "/" +
                std::to_string(id) + ".acc";
}

/**
 * @brief Writes account data to a binary file.
 * The data includes the account ID, name, login, password plaintext.
 * The password is written in plaintext. This is a temporary function to replace encryption algorithms.
 * To be removed when encryption works.
 * The file is created or truncated if it already exists.
 * @throws std::runtime_error if an error occurs while writing the file.
 */
void Account::writeToBin_plaintext() {
    std::ofstream ofs(file_path, std::ios::binary|std::ios::trunc);
    if (!ofs.is_open())
        throw std::runtime_error("Error writing file!");

    ofs.write("ACC", 3); // The header field to identify the file is `ACC` in ASCII
    // write ID
    ofs.write(reinterpret_cast<const char *>(&id), 4);

    // write name
    const auto name_size = static_cast<uint8_t>(name.size());
    ofs.write(reinterpret_cast<const char *>(&name_size), 1);
    ofs.write(name.c_str(), name_size);

    // write login
    const auto login_size = static_cast<uint8_t>(login.size());
    ofs.write(reinterpret_cast<const char *>(&login_size), 1);
    ofs.write(login.c_str(), login_size);


    // write password plaintext
    const auto pass_size = static_cast<uint16_t>(password_plaintext.size());
    ofs.write(reinterpret_cast<const char *>(&pass_size), 2);
    ofs.write(password_plaintext.c_str(), pass_size);

    ofs.close();
}

/**
 * @brief Reads account data from a binary file.
 * The data includes the account ID, name, login, password plaintext.
 * This is a temporary function that uses plaintext password storage. To be removed when encryption works.
 * @throws std::runtime_error if an error occurs while reading the file.
 */
void Account::readFromBin_plaintext() {
    std::ifstream ifs(file_path, std::ios::binary);
    if (!ifs.is_open())
        throw std::runtime_error("Error writing file!");

    ifs.seekg(0);
    char mg_str[3];
    // read header
    ifs.read(mg_str, 3);

    // read id
    ifs.read(reinterpret_cast<char *>(&id), 4);

    // read name
    uint8_t name_size;
    ifs.read(reinterpret_cast<char *>(&name_size), 1);
    char* name_buffer = new char[name_size+1];
    ifs.read(name_buffer, name_size);
    name_buffer[name_size] = '\0';
    name = name_buffer;
    delete []name_buffer;

    // read login
    uint8_t login_size;
    ifs.read(reinterpret_cast<char *>(&login_size), 1);
    char* login_buffer = new char[login_size+1];
    ifs.read(login_buffer, login_size);
    login_buffer[login_size] = '\0';
    login = login_buffer;
    delete []login_buffer;

    // read password plaintext
    uint16_t pass_size;
    ifs.read(reinterpret_cast<char *>(&pass_size), 2);
    char* pass_buffer = new char[pass_size+1];
    ifs.read(pass_buffer, pass_size);
    pass_buffer[pass_size] = '\0';
    password_plaintext = pass_buffer;
    delete []pass_buffer;

    ifs.close();
}

std::ostream& operator<<(std::ostream &os, Account &acc) {
    os << acc.name << "\tlogin: " << acc.login << "\tpassword: ";
    return os;
}

/**
 * @brief Gets the plaintext password.
 * This is a temporary function to replace encryption functionality
 * To be removed when encryption works
 *
 * @return The plaintext password string.
 */
std::string Account::getPassword() {
    return password_plaintext;
}

