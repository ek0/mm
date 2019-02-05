#include "mm.h"
#include <stdio.h>
#include <assert.h>

int main(int argc, char **argv)
{
    enum MMError status = MM_GENERIC_ERROR;
    struct MMState state;

    status = ManualDllLoad(&state, "dummy.dll");
    printf("Status: %d\n", status);
    assert(status == MM_OK);
    status = ManualDllUnload(&state);
    printf("Status: %d\n", status);
    assert(status == MM_OK);
    return 0;
}