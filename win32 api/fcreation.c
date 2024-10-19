#include <Windows.h>
#include <stdio.h>

int main(){
    LPCWSTR filename = L"C:\\Users\\essog\\OneDrive\\Bureau\\hacker.txt";
    HANDLE hFile = CreateFileW(filename, GENERIC_ALL, (FILE_SHARE_READ | FILE_SHARE_WRITE), NULL, OPEN_ALWAYS,  FILE_ATTRIBUTE_NORMAL,NULL);
    
    if (hFile == INVALID_HANDLE_VALUE){
    printf("[-] CreateFileW Api Function Failed With Error : %d\n", GetLastError());
    return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}