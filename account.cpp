#include "account.h"

#include <utility>
#include <openssl/rand.h>
#include <fstream>
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

Account::Account(unsigned int id_, unsigned int user_id_, unsigned int vault_id_):
    name(), login(), id(id_), password()
{
    file_path = "data/" + std::to_string(user_id_) + "/" + std::to_string(vault_id_) + "/" +
            std::to_string(id_) + ".acc";
    readFromBin();
}

Account::Account(unsigned int user_id_, unsigned int vault_id_, std::string name_, std::string login_, Password password_):
    name(std::move(name_)),
    login(std::move(login_)),
    id(0),
    password(std::move(password_))
{
    RAND_bytes(reinterpret_cast<unsigned char*>(&id), sizeof(id));
    file_path = "data/" + std::to_string(user_id_) + "/" + std::to_string(vault_id_) + "/" +
                std::to_string(id) + ".acc";
}

void Account::writeToBin() {
    std::ofstream ofs(file_path, std::ios::binary|std::ios::trunc);
    if (!ofs.is_open())
        throw std::runtime_error("Error writing file!");

    ofs.write("ACC", 3); // The header field to identify the file is `ACC` in ASCII
    // write ID
    ofs.write(reinterpret_cast<const char *>(&id), 4);

    // write name
    const uint8_t name_size = name.size();
    ofs.write(reinterpret_cast<const char *>(&name_size), 1);
    ofs.write(name.c_str(), name_size);

    // write login
    const uint8_t login_size = login.size();
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

std::string Account::getDecryptedPassword(const char *master, int master_len) {
    password.deriveKey(master, master_len);
    return password.decrypt();
}


