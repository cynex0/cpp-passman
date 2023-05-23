#include <cmath>
#include <utility>
#include <openssl/rand.h>
#include <fstream>
#include "vault.h"

Vault::Vault(unsigned int id_): id(id_), security_level(0), iteration_count(0) {
    readFromBin(id_);
}

Vault::Vault(std::string name_, unsigned short sl, const std::string& pass):
    id(0),
    security_level(sl),
    iteration_count((security_level > 0) ? 1000 * int(pow(2, security_level - 1)) : 0),
    name(std::move(name_)),
    masterPassword(iteration_count)
{
    RAND_bytes(reinterpret_cast<unsigned char*>(&id), sizeof(id));
    masterPassword.deriveKey(pass.c_str(), pass.length());
}

void Vault::writeToBin() {
    std::ofstream ofs(std::to_string(id) + ".vlt", std::ios::binary|std::ios::trunc);
    if (!ofs.is_open())
        throw std::runtime_error("Error writing file!");

    ofs.write("VLT", 3); // The header field to identify the file is `VLT` in ASCII
    ofs.write(reinterpret_cast<const char *>(&id), 4);
    ofs.write(reinterpret_cast<const char *>(&security_level), 2);
    const uint16_t name_size = name.size();
    ofs.write(reinterpret_cast<const char *>(&name_size), 1);
    ofs.write(this->name.c_str(), name_size);
    ofs.write(reinterpret_cast<const char *>(masterPassword.getKey()), Password::KEY_LENGTH);
    ofs.write(reinterpret_cast<const char *>(masterPassword.getSalt()), Password::SALT_LENGTH);
    ofs.close();
}

void Vault::readFromBin(unsigned int id_) {
    std::ifstream ifs(std::to_string(id_) + ".vlt", std::ios::binary);
    if (!ifs)
        throw std::runtime_error("Error reading file!");
    ifs.seekg(0);
    char mg_str[3];
    ifs.read(mg_str, 3);

    ifs.read(reinterpret_cast<char *>(&id), 4);
    ifs.read(reinterpret_cast<char *>(&security_level), 2);
    uint16_t name_size = name.size();
    ifs.read(reinterpret_cast<char *>(&name_size), 1);
    char *name_cstr = (char*)malloc(name_size);
    ifs.read(name_cstr, name_size);
    name = std::string(name_cstr);

    unsigned char readKey[Password::KEY_LENGTH];
    ifs.read(reinterpret_cast<char *>(readKey), Password::KEY_LENGTH);

    unsigned char readSalt[Password::SALT_LENGTH]{};
    ifs.read(reinterpret_cast<char *>(readSalt), Password::SALT_LENGTH);

    iteration_count = (security_level > 0) ? 1000 * int(pow(2, security_level - 1)) : 0;
    masterPassword = Password(iteration_count, readKey, readSalt);
    ifs.close();
}

bool Vault::enter(const std::string &pass) {
    return masterPassword.validatePassword(pass);
}

