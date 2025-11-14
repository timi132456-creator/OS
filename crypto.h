#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>

// password(문자열)로부터 16바이트 AES 키를 만들어줌
int derive_key_from_password(const char *password, unsigned char key[16]);

// 16바이트 mask를 AES-128으로 암호화
int encrypt_mask(const unsigned char mask[16],
                 unsigned char out[16],
                 const unsigned char key[16]);

// 암호화된 16바이트를 복호화
int decrypt_mask(const unsigned char enc[16],
                 unsigned char out[16],
                 const unsigned char key[16]);

#endif // CRYPTO_H
