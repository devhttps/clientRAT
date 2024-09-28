# Remote Client with Keylogger, Screenshot Capture, and System Information

This project is a remote client application capable of executing various commands such as capturing keystrokes, taking screenshots, gathering system information, reconnecting to the server, and self-destructing. The client is designed to work on both Windows and Linux systems and communicates with a server through socket connections.

## ⚠️ Important Notice
**This software is for educational purposes only. Unauthorized use of this software for malicious purposes is illegal and unethical. Always obtain permission before deploying it in any environment.**

---

## Table of Contents
- [Prerequisites](#prerequisites)
- [Compilation Instructions](#compilation-instructions)
- [Running the Program](#running-the-program)
- [Setting Up the Server](#setting-up-the-server)
- [Available Commands](#available-commands)
- [Implementation Details](#implementation-details)
- [Troubleshooting](#troubleshooting)
- [Security Disclaimer](#security-disclaimer)
- [License](#license)

---

## Prerequisites

### Windows
- **MinGW**: Minimalist GNU for Windows. Download and install from [MinGW website](http://www.mingw.org/).
- **OpenSSL**: Download and install from [OpenSSL for Windows](https://slproweb.com/products/Win32OpenSSL.html). Ensure the `bin` and `lib` folders of OpenSSL are added to your PATH environment variable.

### Linux
- **GCC**: GNU Compiler Collection
- **OpenSSL**: OpenSSL library for encryption
- Install them using the command:
  ```bash
  sudo apt-get update
  sudo apt-get install gcc libssl-dev

  # Compilation Instructions

To compile the client code, follow the instructions below based on your operating system.

## Compilation on Windows

1. **Install MinGW and OpenSSL:**
   - Ensure MinGW is installed and added to your system's PATH.
   - OpenSSL should also be installed, with `bin` and `lib` folders added to your PATH.

2. **Open Command Prompt or PowerShell:**
   - Use `Win + R`, type `cmd` or `powershell`, and hit `Enter`.

3. **Navigate to the Source Code Directory:**
   - Use the `cd` command to move to the folder containing the source code:
     ```bash
     cd path\to\your\source\code
     ```

4. **Compile the Source Code:**
   - Run the following command:
     ```bash
     gcc -o client.exe your_code.c -lws2_32 -lssl -lcrypto
     ```
   - `-lws2_32`: Links the Winsock library needed for socket programming.
   - `-lssl` and `-lcrypto`: Links the OpenSSL libraries.

5. **Output:**
   - If successful, an executable named `client.exe` will be created in the current directory.

---

## Compilation on Linux

1. **Open a Terminal:**
   - You can use `Ctrl + Alt + T` to open a terminal window.

2. **Navigate to the Source Code Directory:**
   - Use the `cd` command to move to the folder containing your source code:
     ```bash
     cd /path/to/your/source/code
     ```

3. **Compile the Source Code:**
   - Run the following command:
     ```bash
     gcc -o client your_code.c -lssl -lcrypto -lpthread
     ```
   - `-lssl` and `-lcrypto`: Links the OpenSSL libraries.
   - `-lpthread`: Links the pthread library for threading support.

4. **Output:**
   - If successful, an executable named `client` will be created in the current directory.

---

## Running the Program

### On Windows
- After compiling, you should have an executable named `client.exe`.
- Run the program:
  ```bash
  client.exe

### On Linux
- After compiling, you should have an executable named `./client`.
- Run the program:
  ```bash
  ./client

# Setting Up the Server

This client connects to a server that listens on `127.0.0.1` (localhost) and port `4444` by default. Below is a simple example of a Python server you can use:

## Python Server Example

```python
import socket

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('127.0.0.1', 4444))  # IP and PORT must match the client
server.listen(1)

print("Server listening on port 4444...")

client_socket, addr = server.accept()
print(f"Connection from {addr}")

while True:
    command = input("Enter command for client: ")
    client_socket.send(command.encode())
    if command == "exit":
        break

server.close()