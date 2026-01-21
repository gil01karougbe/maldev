#include <windows.h>
#include <winnt.h>
#include <stdio.h>


int main(){
    HMODULE dll_handle = GetModuleHandle("kernel32.dll");
    //DOS HDR
    PIMAGE_DOS_HEADER p_DOS_HDR  = (PIMAGE_DOS_HEADER) dll_handle;

    //NT HEADERS
    PIMAGE_NT_HEADERS p_NT_HDR = (PIMAGE_NT_HEADERS) ((LPBYTE)dll_handle + p_DOS_HDR->e_lfanew );

    //FILE HDR
    IMAGE_FILE_HEADER FILE_HDR = p_NT_HDR->FileHeader;

    //OPTIONAL HDR
    IMAGE_OPTIONAL_HEADER64 OP_HDR = p_NT_HDR->OptionalHeader;

    //EAT
    IMAGE_EXPORT_DIRECTORY* export_table = (IMAGE_EXPORT_DIRECTORY*)((LPBYTE)dll_handle + p_NT_HDR->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    //IAT
    

    return EXIT_SUCCESS;
}
