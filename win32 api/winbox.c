#include <windows.h>

int main(void){
    MessageBoxW(
        NULL,
        L"First Message Box",
        L"Hello world",
        MB_YESNOCANCEL | MB_ICONEXCLAMATION
    );

    return EXIT_SUCCESS;
}

//MessageBoxW==> Wide
//MessageBoxA==> For the ANSI version
//MessageBoxEx==> Extentended version