#include "user.h"
#include <openssl/rand.h>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <cstring>

namespace fs = std::filesystem;

User::User(): id(), time_created(), time_last_accessed() {}

User::User(const std::string& name_): id(0), time_created(time(nullptr)), time_last_accessed(time(nullptr)) {
    name = name_;
    RAND_bytes(reinterpret_cast<unsigned char*>(&id), sizeof(id));
    fs::create_directory("data/" + std::to_string(id));
    file_path = "data/" + std::to_string(id) + "/userData.udt";
}

User::User(unsigned int id_): id(id_), time_created(), time_last_accessed() {
    file_path = "data/" + std::to_string(id) + "/userData.udt";
    readFromBin();
}

void User::writeToBin() {
    std::ofstream ofs(file_path, std::ios::binary|std::ios::trunc);
    if (!ofs.is_open())
        throw std::runtime_error("Error writing file!");

    ofs.write("UDT", 3); // The header field to identify the file is `UDT` in ASCII
    ofs.write(reinterpret_cast<const char *>(&id), 4);
    ofs.write(reinterpret_cast<const char *>(&time_created), sizeof(std::time_t));
    ofs.write(reinterpret_cast<const char *>(&time_last_accessed), sizeof(std::time_t));
    const uint8_t name_size = name.size();
    ofs.write(reinterpret_cast<const char *>(&name_size), 1);
    ofs.write(name.c_str(), name_size);
}

void User::readFromBin() {
    std::ifstream ifs(file_path, std::ios::binary);
    if (!ifs)
        throw std::runtime_error("Error reading file!");

    ifs.seekg(0);
    char mg_str[3];
    ifs.read(mg_str, 3);
//    if (strcmp(mg_str, "UDT") != 0)
//        throw std::runtime_error("Invalid data format!");

    ifs.read(reinterpret_cast<char *>(&id), 4);
    ifs.read(reinterpret_cast<char *>(&time_created), sizeof(std::time_t));
    ifs.read(reinterpret_cast<char *>(&time_last_accessed), sizeof(std::time_t));

    uint8_t name_size = name.size();
    ifs.read(reinterpret_cast<char *>(&name_size), 1);
    char* buffer = new char[name_size+1];
    ifs.read(buffer, name_size);
    buffer[name_size] = '\0';
    name = buffer;
    delete []buffer;
}

unsigned int User::getVaultCount() {
    unsigned int n = 0;
    for (const auto& u_entry : fs::directory_iterator("data/" + std::to_string(id)))
        if(u_entry.is_directory()) n++;
    return n;
}

std::ostream &operator<<(std::ostream &os, const User &user) {
    os << user.id << " " << user.name;
    return os;
}

void User::updateTimeLastAccessed() {
    time_last_accessed = time(nullptr);
    writeToBin();
}

char* User::getTimeLastAccessed() {
    struct tm* timeinfo;
    timeinfo = localtime(&time_last_accessed);
    return asctime(timeinfo);
}

char* User::getTimeCreated() {
    struct tm* timeinfo;
    timeinfo = localtime(&time_created);
    return asctime(timeinfo);
}

