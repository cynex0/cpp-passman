#include <iostream>
#include "password.h"

int main() {
    Password password(10000);
    std::string userPassword = "secretpassword";

    // Encrypt the password
    password.encrypt(userPassword.c_str(), userPassword.length());
    std::cout << password.getEncryptedPassword();

    std::string decryptedPassword = password.decrypt();
    std::cout << "\nDecrypted password: " << decryptedPassword << std::endl;

    return 0;
}
