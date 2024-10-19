/*
    Enc: xor
    ShellCode: read from file
    Desc: 
*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

unsigned char encrypted_shellcode[511];
unsigned char decrypted_shellcode[511];
uint8_t shellcode[1500];
int shellcodeSize; 
char line[200];
int main(){
    //read shellcode 
    FILE *file_pointer;
    char file_name[] = "C:\\Users\\essog\\OneDrive\\Bureau\\WIN-MALWARE-DEV\\shellcode\\stageless\\x64\\calc.txt";
    file_pointer = fopen(file_name, "r");
    if (file_pointer == NULL) {
        printf("Error opening the file.\n");
        return EXIT_FAILURE;
    }
    int Index=0;
    char data[3];
    while (fgets(line, sizeof(line), file_pointer) != NULL) {
        Index=0;
        while(line[Index] != '\0'){
            if(line[Index++]=='x'){
                data[0]=line[Index++];
                data[1]=line[Index++];
                data[2]='\0';
                shellcode[shellcodeSize++] = strtol(data, NULL, 16);
            }
        }
    }
    fclose(file_pointer);
    
    //display the file content
    printf("Initial: \n");
    printf("%c",'"');
    for(int i=1; i<=shellcodeSize; i++){  
        printf("\\x%02x", (uint8_t)shellcode[i-1]);
        if(i%14 == 0){
            printf("%c",'"');
            printf("\n");
            printf("%c",'"');
        }
    }
    printf("%c",'"');
    printf("\n");

    //xor encryption
    char key = 'X';
    for(int i = 0; i<shellcodeSize; i++){
        encrypted_shellcode[i] = shellcode[i]^key;
    }
    
    //print the encrypted
    printf("Encrypted: \n");
    printf("%c",'"');
    for(int i = 1; i<=shellcodeSize; i++){
        printf("\\x%02x", encrypted_shellcode[i-1]);
        if(i%14 == 0){
            printf("%c",'"');
            printf("\n");
            printf("%c",'"');
        }
    }
    printf("%c",'"');
    printf("\n");

    //xor decryption
    for(int i = 0; i<shellcodeSize; i++){
        decrypted_shellcode[i] = encrypted_shellcode[i]^key;
    }
    //print the decrypted
    printf("Decrypted: \n");
    printf("%c",'"');
    for(int i = 1; i<=shellcodeSize; i++){
        printf("\\x%02x",decrypted_shellcode[i-1]);
        if(i%14 == 0){
            printf("%c",'"');
            printf("\n");
            printf("%c",'"');
        }
    }
    printf("%c",'"');
    printf("\n");

    return EXIT_SUCCESS;
}