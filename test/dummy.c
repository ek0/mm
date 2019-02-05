#include <Windows.h>
#include <stdio.h>

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,
    DWORD     fdwReason,
    LPVOID    lpvReserved
)
{
    switch(fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        puts("Dummy DLL Load");
        return TRUE;
    case DLL_PROCESS_DETACH:
        puts("Dummy DLL Unload");
        return TRUE;
    default:
        return TRUE;
    }
}