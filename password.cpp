#include "password.h"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdexcept>
#include <cstring>

/**
 * @brief Constructor for the Password class.
 * Initializes a Password object with the provided iteration count.
 * Generates random salt and IV for encryption.
 *
 * @param itcount The iteration count for key derivation.
 */
Password::Password(int itcount):
    ciphertext_len(0),
    iterationCount(itcount)
{
    // generate salt and iv
    RAND_bytes(saltBytes, SALT_LENGTH);
    RAND_bytes(iv, IV_LENGTH);
}

/**
 * @brief Constructor for the Password class.
 * Initializes a Password object with the provided iteration count, encryption key, and salt.
 * Generates a random IV for encryption.
 *
 * @param itcount The iteration count for key derivation.
 * @param key_ The encryption key.
 * @param salt The salt for key derivation.
 */
Password::Password(int itcount, unsigned char *key_, unsigned char *salt):
    ciphertext_len(0),
    iterationCount(itcount)
{
    std::memcpy(key, key_, KEY_LENGTH);
    std::memcpy(saltBytes, salt, SALT_LENGTH);
    RAND_bytes(iv, IV_LENGTH);
}

/**
 * @brief Constructor for the Password class.
 * Initializes a Password object with the provided iteration count, ciphertext, salt, and IV.
 *
 * @param itcount The iteration count for key derivation.
 * @param ciphertext_ The ciphertext of the encrypted password.
 * @param ciphertext_len_ The length of the ciphertext.
 * @param salt The salt for key derivation.
 * @param iv_ The initialization vector (IV) for encryption.
 */
Password::Password(int itcount, unsigned char *ciphertext_, int ciphertext_len_, unsigned char *salt, unsigned char *iv_):
    ciphertext(ciphertext_),
    ciphertext_len(ciphertext_len_),
    iterationCount(itcount)
{
    std::memcpy(saltBytes, salt, SALT_LENGTH);
    std::memcpy(iv, iv_, IV_LENGTH);
}

/**
 * @brief Derives the encryption key using the provided plaintext and key derivation parameters.
 * Uses the PKCS5_PBKDF2_HMAC_SHA1 function for key derivation.
 *
 * @param plaintext A pointer to the plaintext used for key derivation.
 * @param plaintext_len The length of the plaintext.
 */
void Password::deriveKey(const char *plaintext, size_t plaintext_len) {
    PKCS5_PBKDF2_HMAC_SHA1(plaintext, static_cast<int>(plaintext_len),
                           saltBytes, SALT_LENGTH,
                           iterationCount, KEY_LENGTH, key);
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
void Password::deriveKey(const char *plaintext, size_t plaintext_len, unsigned char *out) {
    PKCS5_PBKDF2_HMAC_SHA1(plaintext, static_cast<int>(plaintext_len),
                           saltBytes, SALT_LENGTH,
                           iterationCount, KEY_LENGTH, out);
}

/**
 * @brief Encrypts the provided plaintext using the stored key and initialization vector (IV).
 * The ciphertext is stored internally in the Password object.
 *
 * @param plaintext A pointer to the plaintext to be encrypted.
 * @param plaintext_len The length of the plaintext.
 */
void Password::encrypt(const char *plaintext, size_t plaintext_len_) {
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    const int blockSize = EVP_CIPHER_block_size(cipher);
    int plaintext_len = static_cast<int>(plaintext_len_);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);

    // Calculate the maximum ciphertext length
    int maxCiphertextLength = plaintext_len + blockSize;
    ciphertext = new unsigned char[maxCiphertextLength];

    int ciphertextLength = 0;
    EVP_EncryptUpdate(ctx, ciphertext, &ciphertextLength, reinterpret_cast<const unsigned char*>(&plaintext), plaintext_len);
    ciphertext_len = ciphertextLength;

    int finalCiphertextLength = 0;
    EVP_EncryptFinal_ex(ctx, ciphertext + ciphertextLength, &finalCiphertextLength);

    finalCiphertextLength += ciphertextLength;
    EVP_CIPHER_CTX_free(ctx);
    this->ciphertext_len = finalCiphertextLength;
}

/**
 * @brief Decrypts the stored ciphertext using the stored key and initialization vector (IV).
 * Returns the decrypted plaintext as a string.
 *
 * @return The decrypted plaintext.
 */
std::string Password::decrypt() const{
    int len;
    int plaintext_len;

    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);
    auto plaintext_buffer = (unsigned char*)malloc(ciphertext_len);

    EVP_DecryptUpdate(ctx, plaintext_buffer, &len, ciphertext, ciphertext_len);

    plaintext_len = len;

    EVP_DecryptFinal_ex(ctx, plaintext_buffer + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    std::string decrypted_string(reinterpret_cast<const char*>(plaintext_buffer), plaintext_len);
    free(plaintext_buffer);
    return decrypted_string;
}

/**
 * @brief Validates a password by deriving a key from the input and comparing it with the stored key.
 *
 * @param input The input password to validate.
 * @return True if the input password is valid, False otherwise.
 */
bool Password::validatePassword(const std::string &input) {
    unsigned char inputKey[KEY_LENGTH];
    deriveKey(input.c_str(), input.size(), inputKey);
    return std::equal(std::begin(inputKey), std::end(inputKey), std::begin(key));
}
