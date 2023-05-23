#include <iostream>
#include "password.h"
#include "vault.h"

int main() {
    Password password;
    std::string userPassword = "newPassword";

    Vault vault(std::string("Vault 1"), 5, userPassword);
    vault.writeToBin();

    Vault vault1(vault.id);
    if (vault1.enter(userPassword))
        std::cout << "IN!!!!";
    return 0;
}
