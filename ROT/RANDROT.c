// Coded by ScratchyCode

// To compile it (on debian based distro) make sure you have the necessary libraries with: sudo apt-get install libssl-dev
// Then compile in gcc with the options -lssl -lcrypto

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <openssl/sha.h>

#define LEN 5000 // max string length

void checkPtr(void *ptr);
void encrypt(unsigned char plainText[], unsigned char key[], char file[]);
void decrypt(char file[], unsigned char key[]);
unsigned char rotl(unsigned char value, unsigned int inc);
unsigned char rotr(unsigned char value, unsigned int inc);
unsigned long long int myPseudoRand(unsigned long long int seed, unsigned long long int salt, unsigned long long int shifter);

int main(void){
    int i=0, menu=0;
    unsigned char *plainText = calloc(LEN,sizeof(unsigned char));
    unsigned char *key = calloc(LEN,sizeof(unsigned char));
    unsigned char *file = calloc(LEN,sizeof(unsigned char));
    
    // check pointers
    checkPtr(plainText);
    checkPtr(key);
    checkPtr(file);
    
    // check 
    if(LEN >= (1ULL << 48)){
        printf("\nString length (LEN) defined incorrectly.\n\n");
        exit(0);
    }
    
    do{
        system("clear");
        printf("\t**************************");
        printf("\n\t*                        *");
        printf("\n\t*    RANDROT encoding    *");
        printf("\n\t*                        *");
        printf("\n\t**************************");
        printf("\n\nMenu:\n1) Encrypt text\n2) Decrypt text\n3) Exit\n");
        printf("\nEnter the number corresponding to the option: ");
        scanf("%d",&menu);
        if(menu < 1 || menu > 3){
            printf("\nInvalid choice!\n");
            exit(1);
        }
        
        getchar();
        switch(menu){
            case 1:
            // encryption
            printf("\nEnter message: ");
            fgets(plainText,LEN,stdin);
            plainText[strlen(plainText)-1] = '\0';
            
            printf("\nEnter password: ");
            fgets(key,LEN,stdin);
            key[strlen(key)-1] = '\0';
            
            printf("\nEnter file name: ");
            fgets(file,LEN,stdin);
            file[strlen(file)-1] = '\0';
            
            // file name control
            for(i=strlen(file); i>0; --i){
                if(file[i-1] == 10 || file[i-1] == 13){
                    file[i-1] = '\0';
                }
            }
            
            encrypt(plainText,key,file);
            
            break;
            
            case 2:
            // decryption
            printf("\nEnter encrypted file name: ");
            fgets(file,LEN,stdin);
            file[strlen(file)-1] = '\0';
            
            printf("\nEnter password: ");
            fgets(key,LEN,stdin);
            key[strlen(key)-1] = '\0';
            
            // file name control
            for(i=strlen(file); i>0; --i){
                if(file[i-1] == 10 || file[i-1] == 13){
                    file[i-1] = '\0';
                }
            }
            
            decrypt(file,key);
            
            break;
            
            case 3:
            // exit
            printf("\n");
            system("clear");
            exit(0);
        }
        
        // clean memory
        memset(plainText,0,LEN);
        memset(key,0,LEN);
        memset(file,0,LEN);
        
        printf("\nDo you want to go back to menu? (Yes = 1 || No = 0): ");
        scanf("%d",&menu);
        menu = (int)menu;
    }while(menu == 1);
    
    system("clear");
    
    // free memory
    free(plainText);
    free(key);
    free(file);
    
    return 0;
}

void encrypt(unsigned char plainText[], unsigned char key[], char file[]){
    unsigned long long int i=0, plainTextLen = strlen(plainText), keyLen = strlen(key);
    unsigned char *encrypted = calloc(LEN,sizeof(unsigned char));
    unsigned char *hash1 = calloc(SHA_DIGEST_LENGTH,sizeof(unsigned char));
    unsigned char *hash2 = calloc(SHA256_DIGEST_LENGTH,sizeof(unsigned char));
    unsigned char *hash3 = calloc(SHA512_DIGEST_LENGTH,sizeof(unsigned char));
    unsigned char *pseudo = calloc(LEN,sizeof(unsigned char));
    
    // check pointers
    checkPtr(encrypted);
    checkPtr(hash1);
    checkPtr(hash2);
    checkPtr(hash3);
    checkPtr(pseudo);
    
    // computing hashes
    SHA1(key,keyLen,hash1);
    SHA256(key,keyLen,hash2);
    SHA512(key,keyLen,hash3);
    
    // generating salt and extract a seed
    unsigned long long int seed, salt, shifter, salt1=0, salt2=0, salt3=0;
    for(i=0; i<SHA_DIGEST_LENGTH; i++){
        salt1 += (unsigned long long int)hash1[i];
    }
    
    for(i=0; i<SHA256_DIGEST_LENGTH; i++){
        salt2 += (unsigned long long int)hash2[i];
    }
    
    for(i=0; i<SHA512_DIGEST_LENGTH; i++){
        salt3 += (unsigned long long int)hash3[i];
    }
    
    // initialization of pseudo-random number generator
    seed = salt2 + salt3;
    salt = salt1 + salt3;
    shifter = (unsigned long long int)(((long double)seed/salt3)*salt);
    
    // computing the pseudo-random characters
    pseudo[0] = seed;
    for(i=1; i<plainTextLen; i++){
        pseudo[i] = (unsigned char)(myPseudoRand(pseudo[i-1],salt,shifter));
    }
    pseudo[plainTextLen] = '\0';
    
    // encryption
    if(seed % 2 == 0){
        // if key length is even
        for(i=0; i<plainTextLen; i++){
            encrypted[i] = rotr(plainText[i],pseudo[i]);
        }
    }else{
        // if key length is odd
        for(i=0; i<plainTextLen; i++){
            encrypted[i] = rotl(plainText[i],pseudo[i]);
        }
    }
    encrypted[plainTextLen] = '\0';
    
    printf("\n\t***Writing file***\n");
    
    FILE *write = fopen(file,"w");
    checkPtr(write);
    
    for(i=0; i<plainTextLen; i++){
    	fprintf(write,"%x ",encrypted[i]);
    }
    fclose(write);
    
    // clean and free memory
    memset(plainText,0,plainTextLen);
    memset(key,0,keyLen);
    memset(pseudo,0,plainTextLen);
    memset(encrypted,0,plainTextLen);
    memset(hash1,0,SHA_DIGEST_LENGTH);
    memset(hash2,0,SHA256_DIGEST_LENGTH);
    memset(hash3,0,SHA512_DIGEST_LENGTH);
    seed = 0;
    salt = 0;
    shifter = 0;
    salt1 = 0;
    salt2 = 0;
    salt3 = 0;
    keyLen = 0;
    
    free(encrypted);
    free(hash1);
    free(hash2);
    free(hash3);
    free(pseudo);
    
    return ;
}

void decrypt(char file[], unsigned char key[]){
    unsigned long long int i=0, encryptedLen=0, keyLen=strlen(key);
    unsigned char *encrypted = calloc(LEN,sizeof(unsigned char));
    unsigned char *decrypted = calloc(LEN,sizeof(unsigned char));
    unsigned char *hash1 = calloc(SHA_DIGEST_LENGTH,sizeof(unsigned char));
    unsigned char *hash2 = calloc(SHA256_DIGEST_LENGTH,sizeof(unsigned char));
    unsigned char *hash3 = calloc(SHA512_DIGEST_LENGTH,sizeof(unsigned char));
    unsigned char *pseudo = calloc(LEN,sizeof(unsigned char));
    
    // check
    checkPtr(encrypted);
    checkPtr(decrypted);
    checkPtr(hash1);
    checkPtr(hash2);
    checkPtr(hash3);
    checkPtr(pseudo);
    
    // computing hashes
    SHA1(key,keyLen,hash1);
    SHA256(key,keyLen,hash2);
    SHA512(key,keyLen,hash3);
    
    // generating salt and extract a seed
    unsigned long long int seed, salt, shifter, salt1=0, salt2=0, salt3=0;
    for(i=0; i<SHA_DIGEST_LENGTH; i++){
        salt1 += (unsigned long long int)hash1[i];
    }
    
    for(i=0; i<SHA256_DIGEST_LENGTH; i++){
        salt2 += (unsigned long long int)hash2[i];
    }
    
    for(i=0; i<SHA512_DIGEST_LENGTH; i++){
        salt3 += (unsigned long long int)hash3[i];
    }
    
    // initialization of pseudo-random number generator    
    seed = salt2 + salt3;
    salt = salt1 + salt3;
    shifter = (unsigned long long int)(((long double)seed/salt3)*salt);
    
    FILE *read = fopen(file,"r");
    checkPtr(read);
    
    i = 0;
    while(fscanf(read,"%x ",&encrypted[i]) != EOF){
        i++;
    }
    encryptedLen = i;
    
    // computing the pseudo random characters
    pseudo[0] = seed;
    for(i=1; i<encryptedLen; i++){
        pseudo[i] = (unsigned char)(myPseudoRand(pseudo[i-1],salt,shifter));
    }
    pseudo[encryptedLen] = '\0';
	fclose(read);
    
    // decryption
    if(seed % 2 == 0){
        // if key length is even
        for(i=0; i<encryptedLen; i++){
            decrypted[i] = rotl(encrypted[i],pseudo[i]);
        }
    }else{
        // if key length is odd
        for(i=0; i<encryptedLen; i++){
            decrypted[i] = rotr(encrypted[i],pseudo[i]);
        }
    }
    decrypted[encryptedLen] = '\0';
    
    printf("\nDecrypted message:\n%s\n",decrypted);
    
    // clean and free memory
    memset(decrypted,0,encryptedLen);
    memset(encrypted,0,encryptedLen);
    memset(pseudo,0,encryptedLen);
    memset(hash1,0,SHA_DIGEST_LENGTH);
    memset(hash2,0,SHA256_DIGEST_LENGTH);
    memset(hash3,0,SHA512_DIGEST_LENGTH);
    seed = 0;
    salt = 0;
    shifter = 0;
    salt1 = 0;
    salt2 = 0;
    salt3 = 0;
    keyLen = 0;
    
    free(encrypted);
    free(decrypted);
    free(hash1);
    free(hash2);
    free(hash3);
    free(pseudo);
    
    return ;
}

void checkPtr(void *ptr){
    
    if(ptr == NULL){
        perror("\nERROR");
        fprintf(stderr,"\n");
        exit(0);
    }
    
    return;
}

unsigned char rotl(unsigned char value, unsigned int inc){
    const unsigned int mask = CHAR_BIT*sizeof(value) - 1;
    inc &= mask;
    return (value << inc) | (value >> (-inc & mask));
}

unsigned char rotr(unsigned char value, unsigned int inc){
    const unsigned int mask = CHAR_BIT*sizeof(value) - 1;
    inc &= mask;
    return (value >> inc) | (value << (-inc & mask));
}

unsigned long long int myPseudoRand(unsigned long long int seed, unsigned long long int salt, unsigned long long int shifter){
    unsigned long long int a, c, m, pseudo;
    
    // lrand48 parameters
    m = 1ULL << 48;
    a = 0x5DEECE66D;
    c = 0xB;
    
    // lrand48 modified
    pseudo = ((a*seed) + c) % m;
    pseudo = (unsigned long long int)(pseudo ^ salt);
    
    if(pseudo % 2 == 0){
        pseudo = rotr(pseudo,shifter);
    }else{
        pseudo = rotl(pseudo,shifter);
    }
    
    seed = 0;
    salt = 0;
    shifter = 0;
    
    return pseudo;
}
