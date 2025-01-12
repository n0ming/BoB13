#include <windows.h>
#include <stdio.h>

extern void MoveShellCode(PVOID ShellCodeBuf);

// This global variable will be used in sc.cc
char* gTARGET_PROG_PATH = (char*)"C:\\Hello.exe";
ULONG gTARGET_PROG_LEN = 0;

int main(int argc, char* argv[])
{
    char* sc = NULL;

    // Allocate virtual memory for shellcode with read/write/execute properties
    sc = (char*)VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (sc == NULL) {
        printf("[-] VirtualAlloc fails: Error Code[%x]\n", GetLastError());
        return -1;
    }

    // Initialize the buffer and global variable
    ZeroMemory(sc, 0x1000);
    gTARGET_PROG_LEN = (ULONG)strlen(gTARGET_PROG_PATH) + 1; // Including null character

    // Move shellcode from text section to buffer memory
    MoveShellCode(sc);

    // Type casting from char buffer to function pointer and call the function
    ((void (*)(void))sc)();

    char ch = getchar();
    return 0;
}
