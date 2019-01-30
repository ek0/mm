#include "mm.h"

#include <Windows.h>
#include <stdio.h>

int FixRelocations(struct MMState *state, IMAGE_BASE_RELOCATION *base_relocation, size_t delta)
{
    size_t i = 0;
    uint16_t* list = NULL;
    uintptr_t* ptr = NULL;
    size_t count = 0;
    uintptr_t image = state->dll_base_addr;

    while(base_relocation->VirtualAddress)
    {
        if(base_relocation->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
        {
            count = (base_relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
            list = (uint16_t*)(base_relocation + sizeof(IMAGE_BASE_RELOCATION));
            for(i = 0; i < count; i++)
            {
                if(list[i])
                {
                    ptr = (uintptr_t*)(image + (base_relocation->VirtualAddress + (list[i] & 0xFFF)));
                    *ptr += delta;
                }
            }
        }
        base_relocation = (base_relocation + base_relocation->SizeOfBlock);
    }
    return MM_OK;
}

int FixImports(struct MMState *state, IMAGE_IMPORT_DESCRIPTOR *import_directory)
{
    void *function = NULL;
    uintptr_t image = state->dll_base_addr;
    IMAGE_THUNK_DATA *FirstThunk, *OrigFirstThunk;
    HMODULE hModule = NULL;
    IMAGE_IMPORT_BY_NAME* image_import;

    while(import_directory->Characteristics)
    {
        OrigFirstThunk = (IMAGE_THUNK_DATA*)(image + import_directory->OriginalFirstThunk);
        FirstThunk = (IMAGE_THUNK_DATA*)(image + import_directory->FirstThunk);
        hModule = LoadLibraryA((LPCSTR)(image + import_directory->Name));
        if(!hModule)
        {
            printf("Error load library...\n");
            return MM_GENERIC_ERROR;
        }
        while(OrigFirstThunk->u1.AddressOfData)
        {
            if(OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                // Ordinal import
                function = GetProcAddress(hModule, (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));
                if(!function)
                {
                    printf("Ordinal GetProcAddress failed\n");
                    return MM_GENERIC_ERROR;
                }
            }
            else
            {
                // Name import
                image_import = (IMAGE_IMPORT_BY_NAME*)(image + OrigFirstThunk->u1.AddressOfData);
                function = GetProcAddress(hModule, image_import->Name);
                if(!function)
                {
                    printf("Import by name failed\n");
                    return MM_GENERIC_ERROR;
                }
            }
            FirstThunk->u1.Function = (ULONGLONG)function;
            OrigFirstThunk++;
            FirstThunk++;
        }
        import_directory++;
    }
    return MM_OK;
}

int ManualDllLoad(struct MMState *state, const char *path)
{
    char* file_buffer = NULL;
    DWORD file_size = 0, number_of_bytes_read = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    IMAGE_DOS_HEADER *dos_header = NULL;
    IMAGE_NT_HEADERS *nt_headers = NULL;
    IMAGE_SECTION_HEADER *section_header = NULL;
    IMAGE_BASE_RELOCATION* base_relocation = NULL;
    IMAGE_IMPORT_DESCRIPTOR* import_directory = NULL;
    uintptr_t image = 0;
    size_t i = 0;
    size_t delta = 0;

    hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if(hFile == INVALID_HANDLE_VALUE)
    {
        return MM_FILE_NOT_FOUND;
    }
    file_size = GetFileSize(hFile, NULL);
    file_buffer = (char*)malloc(file_size);
    if(!file_buffer)
    {
        printf("[-] error allocating file buffer\n");
        CloseHandle(hFile);
        return MM_ALLOC_ERROR;
    }
    if(!ReadFile(hFile, file_buffer, file_size, &number_of_bytes_read, NULL))
    {
        printf("[-] error allocating file buffer\n");
        free(file_buffer);
        CloseHandle(hFile);
        return MM_GENERIC_ERROR; // TODO: fix errors
    }
    // File not needed anymroe, closing
    CloseHandle(hFile);
    dos_header = (IMAGE_DOS_HEADER*)file_buffer;
    nt_headers = (IMAGE_NT_HEADERS*)file_buffer + dos_header->e_lfanew;
    if(dos_header->e_magic != IMAGE_DOS_SIGNATURE ||
       nt_headers->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("Invalid file format");
        free(file_buffer);
        return MM_INVALID_FILE_FORMAT;
    }
    // Allocating new space for the DLL to be mapped
    image = (uintptr_t)VirtualAlloc(NULL, nt_headers->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    state->dll_base_addr = image;
    if(!image)
    {
        printf("[-] error allocating DLL buffer\n");
        free(file_buffer);
        return MM_ALLOC_ERROR;
    }
    // Copying headers
    if (!memcpy((void*)image, file_buffer, nt_headers->OptionalHeader.SizeOfHeaders))
    {
        printf("[-] error copying DLL into space\n");
        free((void*)image);
        free(file_buffer);
        return MM_GENERIC_ERROR;
    }
    section_header = (IMAGE_SECTION_HEADER*)(nt_headers + sizeof(IMAGE_NT_HEADERS));
    // Copying sections into mapped space
    for(i = 0; i < nt_headers->FileHeader.NumberOfSections; i++)
    {
        memcpy((void*)(image + section_header[i].VirtualAddress), file_buffer + section_header[i].PointerToRawData, section_header[i].SizeOfRawData);
    }
    base_relocation = (IMAGE_BASE_RELOCATION*)(image + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    import_directory = (IMAGE_IMPORT_DESCRIPTOR*)(image + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    // Fixing relocations
    // Resolving the delta
    delta = image - nt_headers->OptionalHeader.ImageBase;
    FixRelocations(state, base_relocation, delta);
    // Fixing imports
    FixImports(state, import_directory);
    // Calling DLL EntryPoint
    state->entry_point = (DllProc)(image + nt_headers->OptionalHeader.AddressOfEntryPoint);
    if(state->entry_point)
    {
        state->entry_point((HINSTANCE)image, DLL_PROCESS_ATTACH, NULL);
    }
    return MM_OK;
}

int ManualDllUnload(struct MMState *state)
{
    state->entry_point((HINSTANCE)state->dll_base_addr, DLL_PROCESS_DETACH, NULL);
    free((void*)state->dll_base_addr);
    return MM_OK;
}