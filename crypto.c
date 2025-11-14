#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>

#include "crypto.h"

// 아주 단순한 방식: password 앞에서부터 최대 16바이트를 key로 사용하고,
// 모자라면 뒷부분을 0으로 채움.
int derive_key_from_password(const char *password, unsigned char key[16])
{
    size_t len = strlen(password);
    if (len > 16) len = 16;

    memset(key, 0, 16);
    memcpy(key, password, len);

    return 0;
}

// AES-128-ECB, 패딩 없이 16바이트 블록만 암호화
int encrypt_mask(const unsigned char mask[16],
                 unsigned char out[16],
                 const unsigned char key[16])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        return -1;
    }

    int ret = 0;
    int outlen1 = 0, outlen2 = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1) {
        fprintf(stderr, "EVP_EncryptInit_ex failed\n");
        ret = -1;
        goto cleanup;
    }

    // 패딩 끄기 (정확히 16바이트만 처리)
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (EVP_EncryptUpdate(ctx, out, &outlen1, mask, 16) != 1) {
        fprintf(stderr, "EVP_EncryptUpdate failed\n");
        ret = -1;
        goto cleanup;
    }

    if (EVP_EncryptFinal_ex(ctx, out + outlen1, &outlen2) != 1) {
        fprintf(stderr, "EVP_EncryptFinal_ex failed\n");
        ret = -1;
        goto cleanup;
    }

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int decrypt_mask(const unsigned char enc[16],
                 unsigned char out[16],
                 const unsigned char key[16])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        return -1;
    }

    int ret = 0;
    int outlen1 = 0, outlen2 = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1) {
        fprintf(stderr, "EVP_DecryptInit_ex failed\n");
        ret = -1;
        goto cleanup;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (EVP_DecryptUpdate(ctx, out, &outlen1, enc, 16) != 1) {
        fprintf(stderr, "EVP_DecryptUpdate failed\n");
        ret = -1;
        goto cleanup;
    }

    if (EVP_DecryptFinal_ex(ctx, out + outlen1, &outlen2) != 1) {
        fprintf(stderr, "EVP_DecryptFinal_ex failed\n");
        ret = -1;
        goto cleanup;
    }

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}
