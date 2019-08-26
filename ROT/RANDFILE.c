// Coded by ScratchyCode

/*
To compile it (on debian based distro) make sure you have the necessary libraries with: sudo apt-get install libssl-dev
Then compile in gcc with the options -lssl -lcrypto
*/

// Aggiungere controllo su dimensione file < 2^48 byte
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <time.h>

#define LEN 512
#define MAXLEN 512
#define LOOPS 3

void checkPtr(void *ptr);
void encrypt(char file[], unsigned char key[]);
void decrypt(char file[], unsigned char key[]);
unsigned char rotl(unsigned char value, unsigned int inc);
unsigned char rotr(unsigned char value, unsigned int inc);
long long int dimFile(char filename[]);
int sfe(char filename[], long long int loops);
unsigned long long int myPseudoRand(unsigned long long int seed, unsigned long long int salt, unsigned long long int shifter);

int main(){
    int i, menu=0;
    unsigned char *file = calloc(LEN,sizeof(unsigned char));
    unsigned char *key = calloc(LEN,sizeof(unsigned char));
    unsigned char *key2 = calloc(LEN,sizeof(unsigned char));
    checkPtr(file);
    checkPtr(key);
    checkPtr(key2);
    
    do{
        system("clear");
        printf("\t**************************");
        printf("\n\t*                        *");
        printf("\n\t*    RANDROT encoding    *");
        printf("\n\t*                        *");
        printf("\n\t**************************");
        printf("\n\nMenu:\n1) Encrypt file\n2) Decrypt file\n3) Exit\n");
        printf("\nEnter the number corresponding to the option: ");
        scanf("%d",&menu);
        if(menu<1 || menu>3){
            printf("\nInvalid choice!\n");
            exit(1);
        }
        
        getchar();
        switch(menu){
            case 1:
            // encryption
            printf("\nEnter file name: ");
            fgets(file,LEN,stdin);
            file[strlen(file)-1] = '\0';
            
            printf("\nEnter password: ");
            fgets(key,LEN,stdin);
            key[strlen(key)-1] = '\0';
            
            printf("\nRepeat password: ");
            fgets(key2,LEN,stdin);
            key2[strlen(key2)-1] = '\0';
            if(strcmp(key,key2) != 0){
                printf("\nThe entered passwords do not match!\n");
                exit(0);
            }
            
            // file name control
            for(i=strlen(file); i>0; --i){
                if(file[i-1] == 10 || file[i-1] == 13){
                    file[i-1] = '\0';
                }
            }
            
            encrypt(file,key);
            
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
        
        printf("\nDo you want to go back to menu? (Yes = 1 || No = 0): ");
        scanf("%d",&menu);
        menu = (int)menu;
    }while(menu == 1);
    
    system("clear");
    
    // clean and free memory
    memset(file,0,LEN);
    memset(key,0,LEN);
    memset(key2,0,LEN);
    
    free(file);
    free(key);
    free(key2);
    
    return 0;
}

void encrypt(char file[], unsigned char key[]){
    long long int i=0, lenKey=strlen(key), lenFile=dimFile(file);
    unsigned char textChar, keyChar;
    unsigned char *hash1 = calloc(SHA_DIGEST_LENGTH,sizeof(unsigned char));
    unsigned char *hash2 = calloc(SHA256_DIGEST_LENGTH,sizeof(unsigned char));
    unsigned char *hash3 = calloc(SHA512_DIGEST_LENGTH,sizeof(unsigned char));
    unsigned char *encrypted = calloc(MAXLEN,sizeof(unsigned char));
    checkPtr(hash1);
    checkPtr(hash2);
    checkPtr(hash3);
    checkPtr(encrypted);
    
    // encrypted file name
    char *encFile = calloc(LEN,sizeof(char));
    checkPtr(encFile);
    int error = sprintf(encFile,"%s.rot",file);
    if(error < 0){
        printf("\nError: too large filename.\n");
        exit(1);
    }
    
    printf("\n\t***processing***\n");
    
    // key's hashes
    SHA1(key,lenKey,hash1);
    SHA256(key,lenKey,hash2);
    SHA512(key,lenKey,hash3);
    
    // generating salt to extract a seed
    unsigned long long int seed=0, salt=0, shifter=0, salt1=0, salt2=0, salt3=0;
    for(i=0; i<SHA_DIGEST_LENGTH; i++){
        salt1 += (unsigned long long int)hash1[i];
    }
    
    for(i=0; i<SHA256_DIGEST_LENGTH; i++){
        salt2 += (unsigned long long int)hash2[i];
    }
    
    for(i=0; i<SHA512_DIGEST_LENGTH; i++){
        salt3 += (unsigned long long int)hash3[i];
    }
    
    // initialize the pseudo random number generator
    seed = salt2 + salt3;
    salt = salt1 + salt3;
    shifter = (unsigned long long int)(((long double)seed/salt3)*salt);
    
    // read the plain text file
    FILE *read = fopen(file,"rb");
    checkPtr(read);
    
    // write encrypted file
    FILE *write = fopen(encFile,"wb");
    checkPtr(write);
    
    // file scrolling track
    unsigned long long int bookMark = 0;
    keyChar = seed;
    
    do{
        // encryption
        if(seed % 2 == 0){
            // if key length is even
            for(i=0; i<MAXLEN; i++){
                fscanf(read,"%c",&textChar);
                keyChar = (unsigned char)(myPseudoRand(keyChar,salt,shifter));
                encrypted[i] = rotr(textChar,keyChar);
                fprintf(write,"%c",encrypted[i]);
                bookMark++;
                if(bookMark == lenFile){
                    encrypted[i] = '\0';
                    break;
                }
            }
        }else{
            // if key length is odd
            for(i=0; i<MAXLEN; i++){
                fscanf(read,"%c",&textChar);
                keyChar = (unsigned char)(myPseudoRand(keyChar,salt,shifter));
                encrypted[i] = rotl(textChar,keyChar);
                fprintf(write,"%c",encrypted[i]);
                bookMark++;
                if(bookMark == lenFile){
                    encrypted[i] = '\0';
                    break;
                }
            }
        }
    }while(bookMark < lenFile);
    
    fclose(read);
    fclose(write);
    
    printf("\nFile encryption done.\n");
    
    /*
    // safely delete the plain text file
    sfe(file,LOOPS);
    */
	
	// clean and free memory from plain informations
	memset(key,0,lenKey);
    memset(hash1,0,SHA_DIGEST_LENGTH);
    memset(hash2,0,SHA256_DIGEST_LENGTH);
    memset(hash3,0,SHA512_DIGEST_LENGTH);
    memset(encrypted,0,lenKey);
    memset(encFile,0,LEN);
    
    seed = 0;
    salt = 0;
    shifter = 0;
    salt1 = 0;
    salt2 = 0;
    salt3 = 0;
    lenKey = 0;
    keyChar = 0;
    textChar = 0;
    
    free(hash1);
    free(hash2);
    free(hash3);
    free(encrypted);
    free(encFile);
    
    return ;
}

void decrypt(char file[], unsigned char key[]){
    long long int i=0, lenEncrypted=dimFile(file), lenKey=strlen(key);
    unsigned char textChar=0, keyChar=0;
    unsigned char *hash1 = calloc(SHA_DIGEST_LENGTH,sizeof(unsigned char));
    unsigned char *hash2 = calloc(SHA256_DIGEST_LENGTH,sizeof(unsigned char));
    unsigned char *hash3 = calloc(SHA512_DIGEST_LENGTH,sizeof(unsigned char));
    unsigned char *decrypted = calloc(MAXLEN,sizeof(unsigned char));
    
    checkPtr(hash1);
    checkPtr(hash2);
    checkPtr(hash3);
    checkPtr(decrypted);
    
    printf("\n\t***processing***\n");
    
    // key's hashes
    SHA1(key,lenKey,hash1);
    SHA256(key,lenKey,hash2);
    SHA512(key,lenKey,hash3);
    
    // generating salt to extract a seed
    unsigned long long int seed=0, salt=0, shifter=0, salt1=0, salt2=0, salt3=0;
    for(i=0; i<SHA_DIGEST_LENGTH; i++){
        salt1 += (unsigned long long int)hash1[i];
    }
    
    for(i=0; i<SHA256_DIGEST_LENGTH; i++){
        salt2 += (unsigned long long int)hash2[i];
    }
    
    for(i=0; i<SHA512_DIGEST_LENGTH; i++){
        salt3 += (unsigned long long int)hash3[i];
    }
    
    // initialize the pseudo random number generator
    seed = salt2 + salt3;
    salt = salt1 + salt3;
    shifter = (unsigned long long int)(((long double)seed/salt3)*salt);
    
    // read the encrypted file
    FILE *read = fopen(file,"rb");
    checkPtr(read);
    
    // write the decrypted file
    FILE *write = fopen("Decrypted","wb");
    checkPtr(write);
    
    // file scrolling track
    unsigned long long int bookMark = 0;
    keyChar = seed;
    
    do{
        // decryption
        if(seed % 2 == 0){
            // if key length is even
            for(i=0; i<MAXLEN; i++){
                fscanf(read,"%c",&textChar);                
                keyChar = (unsigned char)(myPseudoRand(keyChar,salt,shifter));
                decrypted[i] = rotl(textChar,keyChar);
                fprintf(write,"%c",decrypted[i]);
                bookMark++;
                if(bookMark == lenEncrypted){
                    decrypted[i] = '\0';
                    break;
                }
            }
        }else{
            // if key length is odd
            for(i=0; i<MAXLEN; i++){
                fscanf(read,"%c",&textChar);
                keyChar = (unsigned char)(myPseudoRand(keyChar,salt,shifter));
                decrypted[i] = rotr(textChar,keyChar);
                fprintf(write,"%c",decrypted[i]);
                bookMark++;
                if(bookMark == lenEncrypted){
                    decrypted[i] = '\0';
                    break;
                }
            }
        }
    }while(bookMark < lenEncrypted);
    
    fclose(read);
    fclose(write);
    
    // clean and free memory from plain informations
    memset(key,0,lenKey);
    memset(hash1,0,SHA_DIGEST_LENGTH);
    memset(hash2,0,SHA256_DIGEST_LENGTH);
    memset(hash3,0,SHA512_DIGEST_LENGTH);
    memset(decrypted,0,MAXLEN);
    
    seed = 0;
    salt = 0;
    shifter = 0;
    salt1 = 0;
    salt2 = 0;
    salt3 = 0;
    lenKey = 0;
    keyChar = 0;
    
    free(hash1);
    free(hash2);
    free(hash3);
    free(decrypted);
    
    printf("\nFile decryption done.\n");
    
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

long long int dimFile(char filename[]){
    long long int dim;
    
    FILE *pf;
    if((pf = fopen(filename,"r")) == NULL){
    	perror("\nDim file");
    	exit(1);
    }
    
    fseek(pf,0,SEEK_END);
    dim = ftell(pf);
    fseek(pf,0,SEEK_SET);
    
    fclose(pf);
    
    return dim;
}

int sfe(char filename[], long long int loops){
    long long int i, j, dim;
    
    srand(time(NULL));
    
    dim = dimFile(filename);
    
    FILE *pf = fopen(filename,"wb");
    if(pf == NULL){
    	perror("\nError");
    	exit(1);
    }
    
    for(i=0; i<LOOPS; i++){
    	// the second for loop is to generate a random string
    	for(j=0; j<dim; j++){
    		fprintf(pf,"%c",rand()%2);
    		fflush(pf);
    	}
    }
    
    fclose(pf);
    if(remove(filename)){
        // file deleted
    	return 0;
    }else{
        // problems to delete file
    	return 1;
    }
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
