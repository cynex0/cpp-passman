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
    name(), login(), id(id_), password()
{
    file_path = "data/" + std::to_string(user_id_) + "/" + std::to_string(vault_id_) + "/" +
            std::to_string(id_) + ".acc";
    readFromBin();
}

/**
 * @brief Constructor for the Account class.
 * Initializes an Account object with the provided user ID, vault ID, name, login, and password.
 * Generates a unique ID for the account.
 * Sets the file path for the account data.
 *
 * @param user_id_ The ID of the user to whom the account belongs.
 * @param vault_id_ The ID of the vault to which the account belongs.
 * @param name_ The name of the account.
 * @param login_ The login information of the account.
 * @param password_ The password of the account.
 */
Account::Account(unsigned int user_id_, unsigned int vault_id_, std::string name_, std::string login_, Password password_):
    name(std::move(name_)),
    login(std::move(login_)),
    id(0),
    password(password_)
{
    RAND_bytes(reinterpret_cast<unsigned char*>(&id), sizeof(id));
    file_path = "data/" + std::to_string(user_id_) + "/" + std::to_string(vault_id_) + "/" +
                std::to_string(id) + ".acc";
}

/**
 * @brief Writes account data to a binary file.
 * The data includes the account ID, name, login, encrypted password, iteration count, salt, and IV.
 * The file is created or truncated if it already exists.
 * @throws std::runtime_error if an error occurs while writing the file.
 */
void Account::writeToBin() {
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

    // write ciphertext
    ofs.write(reinterpret_cast<const char *>(&password.ciphertext_len), 4);
    ofs.write(reinterpret_cast<const char *>(password.ciphertext), password.ciphertext_len);

    // write iteration count
    ofs.write(reinterpret_cast<const char *>(&password.iterationCount), 4);

    // write salt
    ofs.write(reinterpret_cast<const char *>(&password.saltBytes), Password::SALT_LENGTH);

    // write iv
    ofs.write(reinterpret_cast<const char *>(&password.iv), Password::IV_LENGTH);
    ofs.close();
}

/**
 * @brief Reads account data from a binary file.
 * The data includes the account ID, name, login, encrypted password, iteration count, salt, and IV.
 * @throws std::runtime_error if an error occurs while reading the file.
 */
void Account::readFromBin() {
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

    // read ciphertext
    int pass_size;
    ifs.read(reinterpret_cast<char *>(&pass_size), 4);
    auto ciphertext = new unsigned char[pass_size];
    ifs.read(reinterpret_cast<char *>(ciphertext), pass_size);

    // read iteration count
    int iter_c;
    ifs.read(reinterpret_cast<char *>(&iter_c), 4);

    // read salt
    auto salt = new char[Password::SALT_LENGTH];
    ifs.read(salt, Password::SALT_LENGTH);

    // read iv
    auto iv = new char[Password::IV_LENGTH];
    ifs.read(iv, Password::IV_LENGTH);

    password = Password(iter_c, reinterpret_cast<unsigned char *>(ciphertext), pass_size, reinterpret_cast<unsigned char *>(salt),
                        reinterpret_cast<unsigned char *>(iv));

    delete []ciphertext;
    delete []salt;
    delete []iv;
    ifs.close();
}

std::ostream& operator<<(std::ostream &os, Account &acc) {
    os << acc.name << "\tlogin: " << acc.login << "\tpassword: ";
    return os;
}

/**
 * @brief Gets the decrypted password using the provided master key.
 * The master key is used to derive the encryption key for the password.
 *
 * @param master A pointer to the master key.
 * @param master_len The length of the master key.
 * @return The decrypted password as a string.
 */
std::string Account::getDecryptedPassword(const char *master, size_t master_len) {
    password.deriveKey(master, master_len);
    return password.decrypt();
}


