#ifndef _MM_H_
#define _MM_H_

#include <Windows.h>
#include <stdint.h>

typedef BOOL (*DllProc)(HINSTANCE, DWORD, LPVOID);

enum MMError
{
    MM_OK,
    MM_FILE_NOT_FOUND,
    MM_ALLOC_ERROR,
    MM_ACCESS_DENIED,
    MM_ACCESS_VIOLATION,
    MM_INVALID_FILE_FORMAT,
    MM_GENERIC_ERROR
};

struct MMState
{
    uintptr_t dll_base_addr;
    DllProc   entry_point;
};

int ManualDllLoad(struct MMState* state, const char* path);
int ManualDllUnload(struct MMState* state);

#endif // _MM_H_