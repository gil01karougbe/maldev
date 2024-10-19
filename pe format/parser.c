#include <windows.h>
#include <winnt.h>
#include <stdio.h>

void* my_GetProcAddress(HMODULE dll_handle, char* hashed_function_name) {
    IMAGE_DOS_HEADER* p_DOS_HDR  = (IMAGE_DOS_HEADER*) dll_handle;
    IMAGE_NT_HEADERS* p_NT_HDR = (IMAGE_NT_HEADERS*) ((LPBYTE)dll_handle + p_DOS_HDR->e_lfanew ); // NT HEADERS start at the raw offset defined in the e_lfanew header

    IMAGE_EXPORT_DIRECTORY* export_table = (IMAGE_EXPORT_DIRECTORY*)((LPBYTE)dll_handle + p_NT_HDR->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);


    DWORD numberOfNames = export_table->NumberOfNames;
    DWORD* functions_address = (DWORD*)((LPBYTE)dll_handle + export_table->AddressOfFunctions);     // array function
    DWORD* functions_names = (DWORD*)((LPBYTE)dll_handle + export_table->AddressOfNames);           // array name
    WORD*  functions_ordinal = (WORD*)((LPBYTE)dll_handle + export_table->AddressOfNameOrdinals);   // array ordinal

    return EXIT_SUCCESS;
}
