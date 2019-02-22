#include "mm.h"
#include <stdio.h>
#include <assert.h>



int main(int argc, char **argv)
{
    enum MMError status = MM_GENERIC_ERROR;
    struct MMState state;

    status = ManualDllLoadFromFile(&state, "dummy.dll");
    printf("Status: %d\n", status);
    assert(status == MM_OK);
    status = ManualDllUnload(&state);
    printf("Status: %d\n", status);
    assert(status == MM_OK);

    printf("Opening dummy.dll\n");
    char* file_buffer = NULL;
    DWORD file_size = 0, number_of_bytes_read = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;

    hFile = CreateFileA("dummy.dll", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if(hFile == INVALID_HANDLE_VALUE)
    {
        return MM_FILE_NOT_FOUND;
    }
    file_size = GetFileSize(hFile, NULL);
    strncpy_s(state.dll_path, MAX_PATH, "dummy.dll", strlen("dummy.dll"));
    file_buffer = (char*)malloc(file_size);
    if(!file_buffer)
    {
        printf("[-] error allocating file buffer\n");
        CloseHandle(hFile);
        return MM_ALLOC_ERROR;
    }
    if(!ReadFile(hFile, file_buffer, file_size, &number_of_bytes_read, NULL))
    {
        printf("[-] error reading file\n");
        free(file_buffer);
        CloseHandle(hFile);
        return MM_GENERIC_ERROR; // TODO: fix errors
    }
    // File not needed anymroe, closing
    CloseHandle(hFile);
    status = ManualDllLoad(&state, file_buffer);
    printf("Status: %d\n", status);
    assert(status == MM_OK);
    status = ManualDllUnload(&state);
    printf("Status: %d\n", status);
    assert(status == MM_OK);
    free(file_buffer);
    return 0;
}