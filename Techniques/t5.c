/*
    T5: IAT Hooking
    Payload Enc: None
    Payload Obs: None
*/
#include <windows.h>
#include <stdio.h>

int main(){
    HMODULE dllhandle = NULL;
    //dos header
    PIMAGE_DOS_HEADER pdos = (PIMAGE_DOS_HEADER) ((LPBYTE) dllhandle);

    //nt headers
    PIMAGE_NT_HEADERS pnthdr = (PIMAGE_NT_HEADERS) ((LPBYTE)dllhandle + pdos->e_lfanew);

    //iat
    PIMAGE_IMPORT_DESCRIPTOR piat = (PIMAGE_IMPORT_DESCRIPTOR) ((LPBYTE)dllhandle + pnthdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);

    return EXIT_SUCCESS;
}