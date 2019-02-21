// Coded by ScratchyCode
// Designed on the Vernam cipher
/*
To compile it (on debian based distro) make sure you have the necessary libraries with: sudo apt-get install libssl-dev
Then in gcc use the options: -lssl -lcrypto
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <openssl/sha.h>

#define LEN SHA512_DIGEST_LENGTH

void encrypt(unsigned char plain[], unsigned char key[], char file[]);
void decrypt(char file[LEN], unsigned char key[]);
unsigned char rotl(unsigned char value, unsigned int inc);
unsigned char rotr(unsigned char value, unsigned int inc);

int main(){
    int i, menu=0;
    unsigned char plain[LEN];
    unsigned char key[LEN];
    unsigned char file[LEN];
    
    do{
        system("clear");
        printf("\t*************************");
        printf("\n\t*                       *");
        printf("\n\t*    SHAROT encoding    *");
        printf("\n\t*                       *");
        printf("\n\t*************************");
        printf("\n\nMenu:\n1) Encrypt text\n2) Decrypt text\n3) Exit\n");
        printf("\nEnter the number corresponding to the option: ");
        scanf("%d",&menu);

        switch(menu){
            case 1:
            // encryption
            getchar();
            printf("\nEnter message: ");
            fgets(plain,LEN,stdin);
            plain[strlen(plain)-1] = '\0';
    
            printf("\nEnter password: ");
            fgets(key,LEN,stdin);
            key[strlen(key)-1] = '\0';
            
            printf("\nEnter file name: ");
            fgets(file,LEN,stdin);
            file[strlen(file)-1] = '\0';
            
            // control file name
            for(i=strlen(file); i>0; --i){
                if(file[i-1] == 10 || file[i-1] == 13){
                    file[i-1] = '\0';
                }
            }
        
            encrypt(plain,key,file);
        
            break;
        
            case 2:
            // decryption
            getchar();
            printf("\nEnter the encrypted file name: ");
            fgets(file,LEN,stdin);
            file[strlen(file)-1] = '\0';
            
            printf("\nEnter password: ");
            fgets(key,LEN,stdin);
            key[strlen(key)-1] = '\0';
            
            // control file name
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
            exit(0);
        }
    
        printf("\nDo you want to go back to menu? (Yes = 1 || No = 0): ");
        scanf("%d",&menu);
        menu = (int)menu;
    }while(menu == 1);
    
    return 0;
}

void encrypt(unsigned char plain[], unsigned char key[], char file[]){
    long long int i, lenPlain = strlen(plain), lenKey = strlen(key);
    unsigned char encrypted[LEN];
    unsigned char hash[LEN];
    unsigned char plainChar, keyChar;
    
    // calculating key hash with sha512
    SHA512(key,lenKey,hash);    
    
    // encryption
    if(lenKey % 2 == 0){
        // if key length is even
        for(i=0; i<lenPlain; i++){
            plainChar = plain[i];
            keyChar = hash[i];
	        encrypted[i] = rotr(plainChar,keyChar);
        }
    }else{
        // if key length is odd
        for(i=0; i<lenPlain; i++){
            plainChar = plain[i];
            keyChar = hash[i];
	        encrypted[i] = rotl(plainChar,keyChar);
        }
    }
    
    printf("\n\t***Writing file***\n");
    
	FILE *write = fopen(file,"w");
	if(write == NULL){
		perror("\nError");
		exit(1);
	}
	
	for(i=0; i<lenPlain; i++){
		fprintf(write,"%x ",encrypted[i]);
		//printf("%02x ",encrypted[i]);
	}
	
	fclose(write);
	
	// clean password memory
    for(i=0; i<lenKey; i++){
        key[i] = 0;
    }
    // clean plain text memory
    for(i=0; i<lenPlain; i++){
        plain[i] = 0;
    }
    
	return ;
}

void decrypt(char file[], unsigned char key[]){
    long long int i=0, lenEncrypted, lenKey=strlen(key);
    unsigned char encrypted[LEN];
    unsigned char decrypted[LEN];
    unsigned char hash[LEN];
    unsigned char plainChar, keyChar;
    
    // calculating key hash with sha512
    SHA512(key,lenKey,hash);
	
	FILE *read = fopen(file,"r");
	if(read == NULL){
		perror("\nError");
		exit(1);
	}
	
	while(!feof(read)){
	    fscanf(read,"%x ",&encrypted[i]);
	    //printf("%02x ", mist[i]);
	    i++;
	}
	lenEncrypted = i;
	
	fclose(read);

    // decryption
    if(lenKey % 2 == 0){
        // if key length is even
        for(i=0; i<lenEncrypted; i++){
            plainChar = encrypted[i];
            keyChar = hash[i];
	        decrypted[i] = rotl(plainChar,keyChar);
        }
    }else{
        // if key length is odd
        for(i=0; i<lenEncrypted; i++){
            plainChar = encrypted[i];
            keyChar = hash[i];
	        decrypted[i] = rotr(plainChar,keyChar);
        }
    }

    decrypted[lenEncrypted] = '\0';
    
    printf("\nDecrypted text:\n%s\n",decrypted);
    
    // clean password memory
    for(i=0; i<lenKey; i++){
        key[i] = 0;
    }
    // clean decrypted text memory
    for(i=0; i<lenEncrypted; i++){
        decrypted[i] = 0;
    }
    
    return ;
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
