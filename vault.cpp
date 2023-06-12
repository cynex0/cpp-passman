#include <cmath>
#include <utility>
#include <openssl/rand.h>
#include <fstream>
#include "vault.h"
#include <filesystem>
namespace fs = std::filesystem;

/**
 * Constructs a new instance of the Vault class with default values.
 *
 * The constructor initializes a Vault object with empty values for its properties:
 *   - id: The ID of the vault (default constructed).
 *   - security_level: The security level of the vault (default constructed).
 *   - iteration_count: The iteration count for cryptographic operations in the vault (default constructed).
 */
Vault::Vault(): id(), iteration_count(DEFAULT_ITERATION_COUNT) {}

/**
 * Constructs a new instance of the Vault class with the specified ID and user ID for reading from binfile.
 *
 * @param id_        The ID of the vault.
 * @param user_id_   The ID of the user associated with the vault.
 *
 * The constructor initializes a Vault object with the provided ID and user ID.
 * It also sets the security level and iteration count to 0.
 * Additionally, it sets the directory path for the vault based on the user ID and vault ID.
 * Finally, it reads the vault data from the corresponding binary file using the readFromBin() function.
 */
Vault::Vault(unsigned int id_, unsigned int user_id_):
    id(id_),
    iteration_count(DEFAULT_ITERATION_COUNT)
{
    dir_path = "data/" + std::to_string(user_id_) + "/" + std::to_string(id);
    readFromBin();
}

/**
 * Constructs a new instance of the Vault class with the specified user ID, name, security level, and master password.
 *
 * @param user_id_      The ID of the user associated with the vault.
 * @param name_         The name of the vault.
 * @param pass          The master password for the vault.
 *
 * The constructor initializes a Vault object with the provided user ID, name, security level, and master password.
 * It generates a random ID for the vault using the RAND_bytes function.
 * The constructor also sets the directory path for the vault based on the user ID and vault ID.
 * Additionally, it creates a directory with the corresponding directory path using the fs::create_directory function.
 * The constructor then derives a key from the master password using the masterPassword.deriveKey function.
 *
 * Note: The constructor sets the iteration count based on the security level, where the iteration count is calculated as
 *       1000 times 2 raised to the power of (security level - 1) if the security level is greater than 0; otherwise, it
 *       sets the iteration count to 0.
 */
Vault::Vault(unsigned int user_id_, std::string name_, const std::string& pass):
        id(0),
        name(std::move(name_)),
        iteration_count(DEFAULT_ITERATION_COUNT),
        masterPasswordPlaintext(pass)
{
    RAND_bytes(reinterpret_cast<unsigned char*>(&id), sizeof(id));
    RAND_bytes(saltBytes, SALT_LENGTH);

    dir_path = "data/" + std::to_string(user_id_) + "/" + std::to_string(id);
    fs::create_directory(dir_path);

    this->deriveKey(pass.c_str(), pass.size(), this->key);
}

/**
 * @brief Derives the encryption key using the provided plaintext and key derivation parameters.
 * The derived key is stored in the specified output buffer.
 * Uses the PKCS5_PBKDF2_HMAC_SHA1 function for key derivation.
 *
 * @param plaintext A pointer to the plaintext used for key derivation.
 * @param plaintext_len The length of the plaintext.
 * @param out A pointer to the output buffer to store the derived key.
 */
void Vault::deriveKey(const char *plaintext, size_t plaintext_len, unsigned char *out) {
    PKCS5_PBKDF2_HMAC_SHA1(plaintext, static_cast<int>(plaintext_len),
                           saltBytes, SALT_LENGTH,
                           iteration_count, KEY_LENGTH, out);
}

/**
 * Writes the vault data to a binary file.
 *
 * The function creates a binary file named "vaultData.vlt" in the directory path of the vault.
 * It writes the vault data to the file, including the ID, security level, name, master password key, and salt.
 *
 * Note: The file format begins with a header field "VLT" in ASCII to identify the file.
 *
 * @throws std::runtime_error if an error occurs while writing the file.
 */
void Vault::writeToBin() {
    std::ofstream ofs(dir_path + "/vaultData.vlt", std::ios::binary | std::ios::trunc);
    if (!ofs.is_open())
        throw std::runtime_error("Error writing file!");

    ofs.write("VLT", 3); // The header field to identify the file is `VLT` in ASCII
    ofs.write(reinterpret_cast<const char *>(&id), 4);
    const auto name_size = static_cast<uint8_t>(name.size());
    ofs.write(reinterpret_cast<const char *>(&name_size), 1);
    ofs.write(name.c_str(), name_size);
    ofs.write(reinterpret_cast<const char *>(key), KEY_LENGTH);
    ofs.write(reinterpret_cast<const char *>(saltBytes), SALT_LENGTH);
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

    auto name_size = static_cast<uint8_t>(name.size());
    ifs.read(reinterpret_cast<char *>(&name_size), 1);
    char* buffer = new char[name_size+1];
    ifs.read(buffer, name_size);
    buffer[name_size] = '\0';
    name = buffer;
    delete []buffer;

    ifs.read(reinterpret_cast<char *>(this->key), KEY_LENGTH);

    ifs.read(reinterpret_cast<char *>(this->saltBytes), SALT_LENGTH);

    ifs.close();
}

std::ostream &operator<<(std::ostream &os, const Vault &v) {
    os << v.id << ' ' << v.name;
    return os;
}

/**
 * Retrieves the number of accounts stored in the vault.
 *
 * The function counts the number of account files with the extension ".acc" located in the directory path of the vault.
 * It iterates through each file in the directory and increments the count for each file with the ".acc" extension.
 *
 * @return The number of accounts stored in the vault.
*/
unsigned int Vault::getAccountCount() {
    unsigned int n = 0;
    for (const auto& entry : fs::directory_iterator(dir_path))
        if(entry.path().extension() == ".acc") n++;
    return n;
}

/**
 * Validates the provided password against the master password key of the vault.
 *
 * The function checks if the provided password matches the master password of the vault by calling the
 * `validatePassword` function of the `masterPassword` object. It returns the result of the validation.
 *
 * @param pass The password to validate against the master password.
 * @return `true` if the provided password is valid and matches the master password, `false` otherwise.
*/
bool Vault::validateMasterPassword(const std::string &pass) {
    unsigned char inputKey[KEY_LENGTH];
    this->deriveKey(pass.c_str(), pass.size(), inputKey);
    return std::equal(std::begin(inputKey), std::end(inputKey), std::begin(key));
}
