# C++ Password Manager

A simple password manager project written in C++.

## Introduction

This is a C++ password manager project designed to securely store and manage passwords. 
It provides a command-line interface (CLI) for users to create, delete, and retrieve account credentials for various accounts or services.
The password manager uses strong encryption algorithms to ensure the security of stored passwords. It also incorporates hashing techniques and salting to protect against potential security breaches.

## Features
- User, Vault, Account classes
- Data storage in binary files
- Creating multiple users
- Creating multiple vaults for each user
- Creating multiple account entries for each vault
- Adjustable protection level within a vault
- Delete all user data
- Password encryption
- Vault master password validation
- List all stored passwords

## Installation
### Prerequisites
**__This project uses OpenSSL. Make sure OpenSSL is installed on your system before running Passman.__**

Recommended version: **3.1**

For installation instructions refer to OpenSSL repository: https://github.com/openssl/openssl

Installers for Windows available here: https://slproweb.com/products/Win32OpenSSL.html :wink:

You will also need:
- A C++ compiler (e.g., GCC or Clang)
- CMake

### Building
This project can be built with CMake using the included CMakeLists.txt

To build and run Passman, follow these steps:

1. Clone the repository:
   ```shell
   git clone https://github.com/your-username/password-manager.git
   ```
   
2. Create a build directory:
    ```shell
    mkdir build
    cd build
    ```
   
3. Generate the build files using CMake:
    ```shell
    cmake ..
    ```
   
4. Build the project: 
    ```shell
    cmake --build .
    ```
   

## Usage
After running the password manager, you can interact with it using the provided command-line interface. 
The program will guide you through the available options and prompt for necessary inputs.
