// crypto_utils.h
#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>

#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16
#define AES_BLOCK_SIZE 16

int encrypt_data(unsigned char *plaintext, int plaintext_len, 
                 unsigned char *key, unsigned char *iv, 
                 unsigned char *ciphertext);

int decrypt_data(unsigned char *ciphertext, int ciphertext_len, 
                 unsigned char *key, unsigned char *iv, 
                 unsigned char *plaintext);

void handle_errors(void);

#endif
