# C++ Password Manager

A simple password manager project written in C++.

## A note about current state
**This version of Passman is not final. In the current version, passwords are stored in plaintext.**

The encryption/decryption functionality is implemented and works correctly on branch dev-menu, 
but only in readTest() & writeTest() functions (main.cpp). Implementation was not suitable for binary file storage and produced inconsistent behaviour.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)

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
- Password encryption (temprorarily disabled)
- Vault master password validation
- List all stored passwords

## Installation
### Prerequisites
**__This project uses OpenSSL. Make sure OpenSSL is installed on your system before running Passman.__** Recommended version: **3.1**

Installers for __Windows__ available here: https://slproweb.com/products/Win32OpenSSL.html :wink:

On __Linux__, the correct version of OpenSSL can be installed using:
   ```shell
   sudo apt-get install libssl-dev
   ```

For further installation instructions please refer to OpenSSL repository: https://github.com/openssl/openssl

You will also need:
- A C++ compiler (e.g., GCC or Clang)
- CMake

### Building
This project can be built with CMake using the included CMakeLists.txt

To build and run Passman, follow these steps:

1. Clone the repository:
   ```shell
   mkdir repos && cd repos
   git clone https://github.com/cynex0/cpp-passman.git
   cd cpp-passman
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
The built executable 'cpp_passman' will be located in .../cpp-passman/build/Debug

## Usage
After running the password manager, you can interact with it using the provided command-line interface. 
The program will guide you through the available options and prompt for necessary inputs.
