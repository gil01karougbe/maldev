#include <windows.h>
#include <stdio.h>

int main(void){
    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
/*
BOOL CreateProcessA(
  [in, optional]      LPCSTR                lpApplicationName,
  [in, out, optional] LPSTR                 lpCommandLine,
  [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
  [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
  [in]                BOOL                  bInheritHandles,
  [in]                DWORD                 dwCreationFlags,
  [in, optional]      LPVOID                lpEnvironment,
  [in, optional]      LPCSTR                lpCurrentDirectory,
  [in]                LPSTARTUPINFOA        lpStartupInfo,
  [out]               LPPROCESS_INFORMATION lpProcessInformation
);
*/
    if(!CreateProcessW(
        L"C:\\Program Files (x86)\\HashCalc\\HashCalc.exe", //application path
        NULL, //command line parameters
        NULL,
        NULL,
        FALSE,
        BELOW_NORMAL_PRIORITY_CLASS, //process priority
        NULL,
        NULL,
        &si, // Pointer to STARTUPINFO structure
        &pi  // Pointer to PROCESS_INFORMATION structure
        )){
            printf("[-]failed to create process, error: %ld", GetLastError());
            return EXIT_FAILURE;
    }
    printf("[+]process started! pid: %ld", pi.dwProcessId);
    
    return EXIT_SUCCESS;
}
