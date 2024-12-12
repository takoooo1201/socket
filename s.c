#include <sys/socket.h>     // 提供 socket 函數
#include <netinet/in.h>     // 提供 sockaddr_in 結構
#include <string.h>         // 提供字符串處理函數
#include <stdio.h>          // 提供標準輸入輸出
#include <stdlib.h>         // 提供標準庫函數
#include <arpa/inet.h>      // 提供 inet_addr 函數
#include <unistd.h>         // 提供 close 函數
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <sys/select.h>     // 提供 select 函數

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
    struct sockaddr_in server, client;
    int sock, csock, readSize, addressSize;
    char buf[256];
    unsigned char key[32] = "01234567890123456789012345678901"; // 256-bit key
    unsigned char iv[16] = "0123456789012345"; // 128-bit IV
    unsigned char ciphertext[256];
    unsigned char decryptedtext[256];
    int decryptedtext_len, ciphertext_len;
    fd_set readfds;
    int max_sd, sd, activity, i, valread;
    int client_socket[30] = {0};

    bzero(&server, sizeof(server));

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_port = htons(5678);

    sock = socket(PF_INET, SOCK_STREAM, 0);
    bind(sock, (struct sockaddr*)&server, sizeof(server));
    listen(sock, 5);

    addressSize = sizeof(client);

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        max_sd = sock;

        for (i = 0; i < 30; i++) {
            sd = client_socket[i];
            if (sd > 0) FD_SET(sd, &readfds);
            if (sd > max_sd) max_sd = sd;
        }

        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);

        if (FD_ISSET(sock, &readfds)) {
            csock = accept(sock, (struct sockaddr*)&client, &addressSize);
            printf("New connection, socket fd is %d, ip is : %s, port : %d\n",
                   csock, inet_ntoa(client.sin_addr), ntohs(client.sin_port));

            for (i = 0; i < 30; i++) {
                if (client_socket[i] == 0) {
                    client_socket[i] = csock;
                    printf("Adding to list of sockets as %d\n", i);
                    break;
                }
            }
        }

        for (i = 0; i < 30; i++) {
            sd = client_socket[i];

            if (FD_ISSET(sd, &readfds)) {
                if ((valread = read(sd, buf, 256)) == 0) {
                    getpeername(sd, (struct sockaddr*)&client, (socklen_t*)&addressSize);
                    printf("Host disconnected, ip %s, port %d\n",
                           inet_ntoa(client.sin_addr), ntohs(client.sin_port));
                    close(sd);
                    client_socket[i] = 0;
                } else {
                    decryptedtext_len = decrypt((unsigned char*)buf, valread, key, iv, decryptedtext);
                    decryptedtext[decryptedtext_len] = '\0';
                    printf("Read Message: %s", decryptedtext);

                    ciphertext_len = encrypt(decryptedtext, decryptedtext_len, key, iv, ciphertext);
                    send(sd, ciphertext, ciphertext_len, 0);
                }
            }
        }
    }

    close(sock);
    return 0;
}