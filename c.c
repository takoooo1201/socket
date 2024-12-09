#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int main(void) {
    struct sockaddr_in server;
    int sock, readSize;
    char buf[256] = "TCP TEST\n";
    unsigned char key[32] = "01234567890123456789012345678901"; // 256-bit key
    unsigned char iv[16] = "0123456789012345"; // 128-bit IV
    unsigned char ciphertext[256];
    unsigned char decryptedtext[256];
    int decryptedtext_len, ciphertext_len;

    bzero(&server, sizeof(server));

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_port = htons(5678);

    while (1) {
        sock = socket(PF_INET, SOCK_STREAM, 0);
        if (connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
            perror("Connection failed. Retrying in 5 seconds...");
            close(sock);
            sleep(5);
            continue;
        }

        printf("Connected to server.\n");

        do {
            ciphertext_len = encrypt((unsigned char*)buf, strlen(buf), key, iv, ciphertext);
            if (send(sock, ciphertext, ciphertext_len, 0) < 0) {
                perror("Send failed. Reconnecting...");
                break;
            }
            printf("Send Message: %s", buf);

            readSize = recv(sock, buf, sizeof(buf), 0);
            if (readSize <= 0) {
                perror("Receive failed. Reconnecting...");
                break;
            }
            decryptedtext_len = decrypt((unsigned char*)buf, readSize, key, iv, decryptedtext);
            decryptedtext[decryptedtext_len] = '\0';
            printf("Read Message: %s\n", decryptedtext);
        } while (fgets(buf, 255, stdin));

        buf[0] = '\0';
        send(sock, buf, 0, 0);
        printf("Close connection!\n");
        close(sock);
    }

    return 0;
}