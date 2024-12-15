#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/select.h>
#include <errno.h>

#include "crypto_utils.h"

#define MAX_CLIENTS 30
#define BUF_SIZE 256
#define SERVER_PORT 5678

int main(void) {
    int master_sock, client_sockets[MAX_CLIENTS] = {0};
    struct sockaddr_in server_addr, client_addr;
    socklen_t addrlen = sizeof(client_addr);
    fd_set readfds;
    int max_sd, sd, i, activity, valread;

    unsigned char key[AES_KEY_SIZE] = "01234567890123456789012345678901"; 
    unsigned char iv[AES_IV_SIZE]   = "0123456789012345";

    // 建立 Socket
    if ((master_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Master socket creation failed");
        exit(EXIT_FAILURE);
    }

    // 綁定與監聽
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(SERVER_PORT);

    if (bind(master_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(master_sock);
        exit(EXIT_FAILURE);
    }

    if (listen(master_sock, 5) < 0) {
        perror("Listen failed");
        close(master_sock);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", SERVER_PORT);

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(master_sock, &readfds);
        max_sd = master_sock;

        for (i = 0; i < MAX_CLIENTS; i++) {
            sd = client_sockets[i];
            if (sd > 0) FD_SET(sd, &readfds);
            if (sd > max_sd) max_sd = sd;
        }

        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);
        if (activity < 0 && errno != EINTR) {
            perror("Select error");
            break;
        }

        // 新連線
        if (FD_ISSET(master_sock, &readfds)) {
            int new_socket;
            if ((new_socket = accept(master_sock, (struct sockaddr*)&client_addr, &addrlen)) < 0) {
                perror("Accept failed");
                continue;
            }
            printf("New connection: fd %d, IP %s, PORT %d\n",
                   new_socket, inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

            for (i = 0; i < MAX_CLIENTS; i++) {
                if (client_sockets[i] == 0) {
                    client_sockets[i] = new_socket;
                    printf("Added client to index %d\n", i);
                    break;
                }
            }
        }

        // 處理客戶端訊息
        for (i = 0; i < MAX_CLIENTS; i++) {
            sd = client_sockets[i];
            if (sd > 0 && FD_ISSET(sd, &readfds)) {
                unsigned char buf[BUF_SIZE], decrypted[BUF_SIZE], encrypted[BUF_SIZE];
                if ((valread = read(sd, buf, BUF_SIZE)) <= 0) {
                    // 斷線或錯誤
                    if (valread == 0) {
                        getpeername(sd, (struct sockaddr*)&client_addr, &addrlen);
                        printf("Client disconnected: IP %s, PORT %d\n",
                               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
                    } else {
                        perror("Read error");
                    }
                    close(sd);
                    client_sockets[i] = 0;
                } else {
                    // 解密、處理、回應
                    int decrypted_len = decrypt_data(buf, valread, key, iv, decrypted);
                    decrypted[decrypted_len] = '\0';
                    printf("Received from client %d: %s", i, decrypted);

                    // 直接回傳同樣內容（Echo）
                    int encrypted_len = encrypt_data(decrypted, decrypted_len, key, iv, encrypted);
                    if (send(sd, encrypted, encrypted_len, 0) <= 0) {
                        perror("Send error");
                        close(sd);
                        client_sockets[i] = 0;
                    }
                }
            }
        }
    }

    close(master_sock);
    return 0;
}
