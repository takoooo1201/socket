#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <errno.h>

#include "crypto_utils.h"

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 5678
#define BUF_SIZE 256

// 初始化 socket 並嘗試連線
int connect_to_server(const char *ip, int port) {
    struct sockaddr_in server_addr;
    int sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ip);
    server_addr.sin_port        = htons(port);

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return -1;
    }
    return sock;
}

// 設定 socket 超時
int set_socket_timeout(int sock, int seconds) {
    struct timeval timeout;
    timeout.tv_sec  = seconds;
    timeout.tv_usec = 0;

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
        perror("setsockopt (RCVTIMEO) failed");
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
        perror("setsockopt (SNDTIMEO) failed");
        return -1;
    }

    return 0;
}

int main(void) {
    int sock;
    char input_buf[BUF_SIZE];
    unsigned char recv_buf[BUF_SIZE];
    unsigned char key[AES_KEY_SIZE] = "01234567890123456789012345678901"; // 256-bit key
    unsigned char iv[AES_IV_SIZE]   = "0123456789012345";                // 128-bit IV
    unsigned char ciphertext[BUF_SIZE];
    unsigned char decryptedtext[BUF_SIZE];

    while (1) {
        // 嘗試連線
        sock = connect_to_server(SERVER_IP, SERVER_PORT);
        if (sock < 0) {
            // 若連線失敗，等待 5 秒後重試
            fprintf(stderr, "Connection failed. Retrying in 5 seconds...\n");
            sleep(5);
            continue;
        }

        printf("Connected to server.\n");

        // 設定讀寫逾時
        if (set_socket_timeout(sock, 5) < 0) {
            // 若設定逾時失敗，可視情況選擇是否要斷線重連
            // 此處直接關閉，並嘗試重連
            close(sock);
            fprintf(stderr, "Failed to set socket timeouts. Reconnecting...\n");
            sleep(5);
            continue;
        }

        printf("Enter messages to send to the server:\n");

        // 主回圈：讀取使用者輸入並傳送至伺服器
        while (fgets(input_buf, sizeof(input_buf), stdin)) {
            if (strlen(input_buf) == 0) {
                // 若無輸入內容，直接繼續等待下一次輸入
                continue;
            }

            // 加密輸入字串
            int ciphertext_len = encrypt_data((unsigned char*)input_buf, (int)strlen(input_buf), key, iv, ciphertext);
            if (ciphertext_len <= 0) {
                fprintf(stderr, "Encryption failed. Retrying connection...\n");
                close(sock);
                break;
            }

            // 傳送加密後的資料給伺服器
            if (send(sock, ciphertext, ciphertext_len, 0) <= 0) {
                perror("Send failed. Reconnecting...");
                close(sock);
                break;
            }
            printf("Sent Message (Plaintext): %s", input_buf);

            // 接收伺服器回覆
            int readSize = recv(sock, recv_buf, sizeof(recv_buf), 0);
            if (readSize > 0) {
                int decrypted_len = decrypt_data((unsigned char*)recv_buf, readSize, key, iv, decryptedtext);
                if (decrypted_len < 0) {
                    fprintf(stderr, "Decryption failed. Reconnecting...\n");
                    close(sock);
                    break;
                }
                decryptedtext[decrypted_len] = '\0';
                printf("Received Message: %s\n", decryptedtext);
            } else if (readSize == 0) {
                printf("Server closed the connection. Reconnecting...\n");
                close(sock);
                break;
            } else {
                // 若 readSize < 0 為錯誤或逾時
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    printf("Receive timeout occurred. Reconnecting...\n");
                } else {
                    perror("Receive failed. Reconnecting...");
                }
                close(sock);
                break;
            }
        }
    }

    return 0;
}
