/*
 * SysWhispers4 — Example: Token Privilege Manipulation via NT syscalls
 *
 * FOR AUTHORIZED SECURITY TESTING AND RESEARCH ONLY.
 * Unauthorized use against systems you do not own is illegal.
 *
 * Technique:
 *   1. Open current process token
 *   2. Query token information (integrity level, privileges)
 *   3. Enable SeDebugPrivilege to allow debugging other processes
 *   4. Duplicate the token for impersonation
 *
 * Generated with:
 *   python syswhispers.py --preset token --method indirect --resolve freshycalls
 *
 * Compile (MSVC):
 *   cl /nologo /W3 example_token_manipulation.c SW4Syscalls.c SW4Syscalls.asm advapi32.lib
 *
 * Compile (MinGW):
 *   x86_64-w64-mingw32-gcc -masm=intel example_token_manipulation.c SW4Syscalls.c SW4Syscalls_stubs.c -o token.exe -ladvapi32
 */
#include <stdio.h>
#include <string.h>
#include "SW4Syscalls.h"

/* SeDebugPrivilege LUID is always {20, 0} on Windows */
#define SE_DEBUG_PRIVILEGE_LUID 20

static void print_integrity_level(HANDLE hToken) {
    ULONG needed = 0;
    /* First call to get required size */
    SW4_NtQueryInformationToken(
        hToken, TokenIntegrityLevel, NULL, 0, &needed
    );
    if (needed == 0) {
        printf("[*] Could not query integrity level size\n");
        return;
    }

    BYTE buffer[256];
    if (needed > sizeof(buffer)) {
        printf("[*] Integrity level buffer too small\n");
        return;
    }

    NTSTATUS status = SW4_NtQueryInformationToken(
        hToken, TokenIntegrityLevel, buffer, sizeof(buffer), &needed
    );
    if (!NT_SUCCESS(status)) {
        printf("[*] NtQueryInformationToken(IntegrityLevel) failed: 0x%08X\n", status);
        return;
    }

    TOKEN_MANDATORY_LABEL *tml = (TOKEN_MANDATORY_LABEL *)buffer;
    DWORD integrityLevel = *GetSidSubAuthority(
        tml->Label.Sid,
        (DWORD)(UCHAR)(*GetSidSubAuthorityCount(tml->Label.Sid) - 1)
    );

    const char *levelStr = "Unknown";
    if (integrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
        levelStr = "System";
    else if (integrityLevel >= SECURITY_MANDATORY_HIGH_RID)
        levelStr = "High";
    else if (integrityLevel >= SECURITY_MANDATORY_MEDIUM_RID)
        levelStr = "Medium";
    else if (integrityLevel >= SECURITY_MANDATORY_LOW_RID)
        levelStr = "Low";

    printf("[+] Token integrity level: %s (0x%04X)\n", levelStr, integrityLevel);
}

int main(void) {
    NTSTATUS status;
    HANDLE hToken = NULL;

    /* Step 0: Initialize SysWhispers4 runtime */
    if (!SW4_Initialize()) {
        fprintf(stderr, "[!] SW4_Initialize failed\n");
        return 1;
    }
    printf("[+] SysWhispers4 initialized\n");

    /* Step 1: Open our own process token */
    status = SW4_NtOpenProcessToken(
        (HANDLE)-1,     /* NtCurrentProcess() */
        TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_DUPLICATE,
        &hToken
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtOpenProcessToken failed: 0x%08X\n", status);
        return 1;
    }
    printf("[+] Opened process token (handle 0x%p)\n", hToken);

    /* Step 2: Query and display integrity level */
    print_integrity_level(hToken);

    /* Step 3: Enable SeDebugPrivilege */
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid.LowPart  = SE_DEBUG_PRIVILEGE_LUID;
    tp.Privileges[0].Luid.HighPart = 0;
    tp.Privileges[0].Attributes    = SE_PRIVILEGE_ENABLED;

    TOKEN_PRIVILEGES oldTp;
    ULONG returnLen = 0;

    status = SW4_NtAdjustPrivilegesToken(
        hToken,
        FALSE,          /* DisableAllPrivileges = FALSE */
        &tp,
        sizeof(oldTp),
        &oldTp,
        &returnLen
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtAdjustPrivilegesToken failed: 0x%08X\n", status);
        if (status == (NTSTATUS)0xC0000061)
            fprintf(stderr, "    Hint: run as Administrator to enable SeDebugPrivilege\n");
        SW4_NtClose(hToken);
        return 1;
    }
    printf("[+] SeDebugPrivilege enabled successfully\n");

    /* Step 4: Duplicate the token for impersonation */
    HANDLE hDupToken = NULL;
    OBJECT_ATTRIBUTES objAttr = { sizeof(OBJECT_ATTRIBUTES) };
    SECURITY_QUALITY_OF_SERVICE sqos;
    sqos.Length              = sizeof(sqos);
    sqos.ImpersonationLevel = SecurityImpersonation;
    sqos.ContextTrackingMode = FALSE;
    sqos.EffectiveOnly       = FALSE;
    objAttr.SecurityQualityOfService = &sqos;

    status = SW4_NtDuplicateToken(
        hToken,
        TOKEN_ALL_ACCESS,
        &objAttr,
        FALSE,                  /* EffectiveOnly */
        TokenImpersonation,     /* Impersonation token */
        &hDupToken
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtDuplicateToken failed: 0x%08X\n", status);
        SW4_NtClose(hToken);
        return 1;
    }
    printf("[+] Token duplicated as impersonation token (handle 0x%p)\n", hDupToken);

    /* Display integrity level of duplicated token */
    printf("[*] Duplicated token info:\n");
    print_integrity_level(hDupToken);

    /* Cleanup */
    SW4_NtClose(hDupToken);
    SW4_NtClose(hToken);
    printf("[+] Token manipulation complete.\n");
    return 0;
}
