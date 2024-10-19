#include <stdio.h>

unsigned long hash_djb2(unsigned char *str){
    unsigned long hash = 5381;
    int c;
    while (c = *str++){
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    return hash;
}

int main(){
    char hash_str[100];
    char func[] = "OpenProcess";
    unsigned long hash = hash_djb2(func);
    sprintf(hash_str, "%lu", hash);
    printf("Hash as string: %s\n", hash_str);
    return 0;
}