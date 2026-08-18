#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int useSalt; // flag for using salt or not

#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define SALT_SIZE 8
#define BUFFER_SIZE 1024

// must have salt or no salt option, 
// if salt then randomly generate salt for encryption and read salt from input file (encrypted file) for decryption

// uses password to generate key and iv using EVP_BytesToKey function
void initAES(const char *pass, unsigned char *key, unsigned char *iv, unsigned char *salt)
{
    memset(key, 0, AES_KEY_SIZE);
    memset(iv, 0, AES_BLOCK_SIZE); 

  if (useSalt == 0) {
    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), NULL, (unsigned char*)pass, strlen(pass), 1, key, iv);
  }
  else {
    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, (unsigned char*)pass, strlen(pass), 1, key, iv);
  }
}

int encrypt(FILE *plaintextFile, FILE *encryptedFile, unsigned char *pass) {

    unsigned char key[AES_KEY_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char salt[8];

    // blocks for encryption
    unsigned char readInputBuffer[1024]; // reading from file, in this case plaintextFile
    unsigned char encryptedCipherBuffer[1024 + EVP_MAX_BLOCK_LENGTH]; // outputting encyrpted data to new encrypted file, in this case encryptedFile
    int readBytes, encryptedBytes;

    if (useSalt) {
        fwrite("Salted__", 1, 8, encryptedFile);
        RAND_bytes(salt, 8);
        fwrite(salt, 1, 8, encryptedFile);

        printf("Salt: ");
        for (int i = 0; i < SALT_SIZE; i++) {
            printf("%02x", salt[i]);
        }
        printf("\n");
    }

    initAES(pass, key, iv, salt);

    printf("Key: ");
    for (int i = 0; i < AES_KEY_SIZE; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");

    printf("IV: ");
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        printf("%02x", iv[i]);
    }
    printf("\n");

    EVP_CIPHER_CTX *ctx;
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        handleErrors();
    }
    
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        handleErrors();
    }    

    while ((readBytes = fread(readInputBuffer, 1, BUFFER_SIZE, plaintextFile)) > 0) {
        if(1 != EVP_EncryptUpdate(ctx, encryptedCipherBuffer, &encryptedBytes, readInputBuffer, readBytes)) {
            handleErrors();
        }
        fwrite(encryptedCipherBuffer, 1, encryptedBytes, encryptedFile);
    }

    if(1 != EVP_EncryptFinal_ex(ctx, encryptedCipherBuffer, &encryptedBytes)) {
        handleErrors();
    }
    fwrite(encryptedCipherBuffer, 1, encryptedBytes, encryptedFile);

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

int decrypt(FILE *encryptedFile, FILE *plaintextFile, unsigned char *pass) {

    unsigned char key[AES_KEY_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char salt[8];

    // blocks for decryption
    unsigned char readInputBuffer[1024]; // reading from file, in this case encryptedFile
    unsigned char decryptedCipherBuffer[1024 + EVP_MAX_BLOCK_LENGTH]; // outputting decrypted data to decrypted file, in this case plaintextFile
    int readBytes, decryptedBytes;
    
    if (useSalt) {
        fseek(encryptedFile, 8, SEEK_SET);
        fread(salt, 1, 8, encryptedFile);

        printf("Salt: ");
        for (int i = 0; i < SALT_SIZE; i++) {
            printf("%02x", salt[i]);
        }
        printf("\n");
    }

    initAES(pass, key, iv, salt);

    printf("Key: ");
    for (int i = 0; i < AES_KEY_SIZE; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");

    printf("IV: ");
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        printf("%02x", iv[i]);
    }
    printf("\n");

    EVP_CIPHER_CTX *ctx;
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        handleErrors();
    }
    
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        handleErrors();
    }
    
    while ((readBytes = fread(readInputBuffer, 1, BUFFER_SIZE, encryptedFile)) > 0) {
        if(1 != EVP_DecryptUpdate(ctx, decryptedCipherBuffer, &decryptedBytes, readInputBuffer, readBytes)) {
            handleErrors();
        }
        fwrite(decryptedCipherBuffer, 1, decryptedBytes, plaintextFile);
    }

    if(1 != EVP_DecryptFinal_ex(ctx, decryptedCipherBuffer, &decryptedBytes)) {
        handleErrors();
    }
    fwrite(decryptedCipherBuffer, 1, decryptedBytes, plaintextFile);

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}


int main(int argc, char *argv[]) {

    // take input file, output file, encryption/decryption mode, password, and salt from command line arguments
    // ./main.c inputFile outputFile enc/dec password nosalt

    if (argc < 5) {
        printf("Usage: %s <inputFile> <outputFile> <e/d> <password> <nosalt>\n", argv[0]);
        return 1;
    }

    if (argc >= 6) {
        useSalt = strcmp(argv[5], "nosalt");
    }
    else {
        useSalt = 1;
    }

    // password given from command line argument
    // key and iv generated from password and EVP_BytesToKey function
    // salt generated from RAND_bytes function

    FILE *inputFile = fopen(argv[1], "rb");
    FILE *outputFile = fopen(argv[2], "wb");

    if (strcmp(argv[3], "e") == 0) {

        // input file is plaintext, output file is encrypted file
        if (encrypt(inputFile, outputFile, (unsigned char*)argv[4])) {
            printf("Encryption successful.\n");
        }
        else {
            printf("Encryption failed.\n");
        }
    }
    else {
        
        // TODO: nosalt parameter in command line required for decryption of files encrypted without salt, find way to fix that
        // input file is encrypted file, output file is decrypted plaintext file
        if (decrypt(inputFile, outputFile, (unsigned char*)argv[4])) {
            printf("Decryption successful.\n");
        }
        else {
            printf("Decryption failed.\n");
        }
    }

    
    return 0;
}