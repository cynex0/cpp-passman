#include "user.h"
#include <openssl/rand.h>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <cstring>

namespace fs = std::filesystem;

/**
 * @brief Default constructor for the User class.
 * Initializes a User object with default values for id, time_created, and time_last_accessed.
 */
User::User(): id(), time_created(), time_last_accessed() {}

/**
 * @brief Constructor for the User class.
 * Initializes a User object with the provided name and generates unique ID.
 * Creates a directory and file for user data.
 *
 * @param name_ The name of the user.
 */
User::User(const std::string& name_): id(0), time_created(time(nullptr)), time_last_accessed(time(nullptr)) {
    name = name_;
    RAND_bytes(reinterpret_cast<unsigned char*>(&id), sizeof(id));
    fs::create_directory("data/" + std::to_string(id));
    file_path = "data/" + std::to_string(id) + "/userData.udt";
}

/**
 * @brief Constructor for the User class for reading from binfile.
 * Initializes a User object with the provided ID.
 * Sets the time_created and time_last_accessed to default values.
 * Sets the file path for user data and reads data from the binary file.
 *
 * @param id_ The ID of the user.
 */
User::User(unsigned int id_): id(id_), time_last_accessed() {
    file_path = "data/" + std::to_string(id) + "/userData.udt";
    readFromBin();
}

/**
 * @brief Writes user data to a binary file.
 * The data includes the user ID, creation time, last access time, and user name.
 * The file is created or truncated if it already exists.
 * @throws std::runtime_error if an error occurs while writing the file.
 */
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

/**
 * @brief Reads user data from a binary file.
 * The file is assumed to contain the user ID, creation time, last access time, and user name.
 * @throws std::runtime_error if an error occurs while reading the file.
 */
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

/**
 * @brief Returns the number of vaults associated with the user.
 * Counts the number of directories in the user's data directory.
 *
 * @return The number of vaults associated with the user.
 */
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

/**
 * @brief Updates the last access time of the user to the current time and writes the changes to the binary file.
 */
void User::updateTimeLastAccessed() {
    time_last_accessed = time(nullptr);
    writeToBin();
}

/**
 * @brief Returns a C-style string representing the last access time of the user.
 * The time is formatted as a string using the `asctime` function.
 *
 * @return A C-style string representing the last access time of the user.
 */
char* User::getTimeLastAccessed() {
    struct tm* timeinfo;
    timeinfo = localtime(&time_last_accessed);
    return asctime(timeinfo);
}

/**
 * @brief Returns a C-style string representing the creation time of the user.
 * The time is formatted as a string using the `asctime` function.
 *
 * @return A C-style string representing the creation time of the user.
 */
char* User::getTimeCreated() {
    struct tm* timeinfo;
    timeinfo = localtime(&time_created);
    return asctime(timeinfo);
}

