#include <windows.h>
#include <fstream>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID)
{
    if (fdwReason == DLL_PROCESS_ATTpythonACH)
    {
        DisableThreadLibraryCalls(hinstDLL);

        std::ofstream log("\\127.0.0.1\\share\\dll_log.txt", std::ios::app);
        if (log.is_open())
        {
            log << "DLL loaded into process PID: "
                << GetCurrentProcessId() << "\n";
            log.close();
        }
    }
    return TRUE;
}
