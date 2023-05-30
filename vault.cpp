#include <cmath>
#include <utility>
#include <openssl/rand.h>
#include <fstream>
#include "vault.h"
#include "account.h"
#include <filesystem>
namespace fs = std::filesystem;

Vault::Vault(): id(), security_level(), iteration_count() {}

Vault::Vault(unsigned int id_, unsigned int user_id_):
    id(id_),
    security_level(0),
    iteration_count(0)
{
    dir_path = "data/" + std::to_string(user_id_) + "/" + std::to_string(id);
    readFromBin();
}

Vault::Vault(unsigned int user_id_, std::string name_, unsigned short sl, const std::string& pass):
    id(0),
    name(std::move(name_)),
    security_level(sl),
    iteration_count((security_level > 0) ? 1000 * int(pow(2, security_level - 1)) : 0),
    masterPassword(),
    masterPasswordPlaintext(pass)
{
    RAND_bytes(reinterpret_cast<unsigned char*>(&id), sizeof(id));

    dir_path = "data/" + std::to_string(user_id_) + "/" + std::to_string(id);
    fs::create_directory(dir_path);

    masterPassword.deriveKey(pass.c_str(), pass.length());
}

void Vault::writeToBin() {
    std::ofstream ofs(dir_path + "/vaultData.vlt", std::ios::binary | std::ios::trunc);
    if (!ofs.is_open())
        throw std::runtime_error("Error writing file!");

    ofs.write("VLT", 3); // The header field to identify the file is `VLT` in ASCII
    ofs.write(reinterpret_cast<const char *>(&id), 4);
    ofs.write(reinterpret_cast<const char *>(&security_level), 2);
    const uint8_t name_size = name.size();
    ofs.write(reinterpret_cast<const char *>(&name_size), 1);
    ofs.write(name.c_str(), name_size);
    ofs.write(reinterpret_cast<const char *>(masterPassword.key), Password::KEY_LENGTH);
    ofs.write(reinterpret_cast<const char *>(masterPassword.saltBytes), Password::SALT_LENGTH);
    ofs.close();
}

void Vault::readFromBin() {
    std::ifstream ifs(dir_path + "/vaultData.vlt", std::ios::binary);
    if (!ifs)
        throw std::runtime_error("Error reading file!");

    ifs.seekg(0);
    char mg_str[3];
    ifs.read(mg_str, 3);

    ifs.read(reinterpret_cast<char *>(&id), 4);
    ifs.read(reinterpret_cast<char *>(&security_level), 2);

    uint8_t name_size = name.size();
    ifs.read(reinterpret_cast<char *>(&name_size), 1);
    char* buffer = new char[name_size+1];
    ifs.read(buffer, name_size);
    buffer[name_size] = '\0';
    name = buffer;
    delete []buffer;

    unsigned char readKey[Password::KEY_LENGTH];
    ifs.read(reinterpret_cast<char *>(readKey), Password::KEY_LENGTH);

    unsigned char readSalt[Password::SALT_LENGTH];
    ifs.read(reinterpret_cast<char *>(readSalt), Password::SALT_LENGTH);

    iteration_count = (security_level > 0) ? 1000 * int(pow(2, security_level - 1)) : 0;
    masterPassword = Password(Password::DEFAULT_ITERATION_COUNT, readKey, readSalt);

    ifs.close();
}

Password Vault::createNewPassword(const std::string& password_plaintext) {
    Password password(iteration_count);
    password.deriveKey(masterPasswordPlaintext.c_str(), masterPasswordPlaintext.size());
    password.encrypt(password_plaintext.c_str(), password_plaintext.size());
    return password;
}

std::ostream &operator<<(std::ostream &os, const Vault &v) {
    os << v.id << ' ' << v.name;
    return os;
}

unsigned int Vault::getAccountCount() {
    unsigned int n = 0;
    for (const auto& entry : fs::directory_iterator(dir_path))
        if(entry.path().extension() == ".acc") n++;
    return n;
}

bool Vault::validateMasterPassword(const std::string &pass) {
    return masterPassword.validatePassword(pass);
}
