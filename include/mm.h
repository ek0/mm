#ifndef _MM_H_
#define _MM_H_

#include "mm_export_config.h"

#include <Windows.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef BOOL (*DllProc)(HINSTANCE, DWORD, LPVOID);

enum MMError
{
    MM_OK,
    MM_FILE_NOT_FOUND,
    MM_ALLOC_ERROR,
    MM_ACCESS_DENIED,
    MM_ACCESS_VIOLATION,
    MM_INVALID_FILE_FORMAT,
    MM_ERROR_CALLING_OEP,
    MM_GENERIC_ERROR
};

struct MMState
{
    char      dll_path[MAX_PATH];
    uintptr_t dll_base_addr;
    DllProc   entry_point;
};

int MM_EXPORT ManualDllLoad(struct MMState* state, const char* path);
int MM_EXPORT ManualDllUnload(struct MMState* state);

#ifdef __cplusplus
}
#endif

#endif // _MM_H_