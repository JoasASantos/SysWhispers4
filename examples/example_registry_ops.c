/*
 * example_registry_ops.c -- SysWhispers4 Registry Operations Example
 *
 * Demonstrates NT syscall-based registry manipulation:
 *   - NtCreateKey / NtOpenKey
 *   - NtSetValueKey / NtQueryValueKey
 *   - NtEnumerateKey / NtEnumerateValueKey
 *   - NtDeleteKey
 *
 * FOR AUTHORIZED SECURITY TESTING AND RESEARCH ONLY.
 * Compile (MSVC):
 *   cl /nologo example_registry_ops.c SW4Syscalls.c SW4Syscalls.asm /link ntdll.lib
 * Compile (MinGW):
 *   x86_64-w64-mingw32-gcc -masm=intel example_registry_ops.c SW4Syscalls.c SW4Syscalls_stubs.c -o registry_ops.exe
 */

#include <stdio.h>
#include <string.h>
#include "SW4Syscalls.h"

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);          \
    (p)->RootDirectory = r;                           \
    (p)->Attributes = a;                              \
    (p)->ObjectName = n;                              \
    (p)->SecurityDescriptor = s;                      \
    (p)->SecurityQualityOfService = NULL;             \
}
#endif

#define OBJ_CASE_INSENSITIVE 0x00000040L

int main(void)
{
    printf("[*] SysWhispers4 Registry Operations Example\n");
    printf("[*] FOR AUTHORIZED SECURITY TESTING ONLY\n\n");

    if (!SW4_Initialize()) {
        printf("[-] SW4_Initialize failed\n");
        return 1;
    }
    printf("[+] SysWhispers4 initialized\n");

    NTSTATUS status;
    HANDLE hKey = NULL;
    ULONG disposition = 0;

    /* Build registry path: HKCU\Software\SW4Test */
    UNICODE_STRING keyPath;
    keyPath.Buffer = L"\\Registry\\CurrentUser\\Software\\SW4Test";
    keyPath.Length = (USHORT)(wcslen(keyPath.Buffer) * sizeof(WCHAR));
    keyPath.MaximumLength = keyPath.Length + sizeof(WCHAR);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &keyPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    /* Step 1: Create or open the registry key */
    printf("[*] Creating registry key: HKCU\\Software\\SW4Test\n");
    status = SW4_NtCreateKey(
        &hKey,
        KEY_ALL_ACCESS,
        &oa,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        &disposition
    );
    if (!NT_SUCCESS(status)) {
        printf("[-] NtCreateKey failed: 0x%08X\n", (unsigned int)status);
        return 1;
    }
    printf("[+] Key %s (handle: 0x%p)\n",
        disposition == REG_CREATED_NEW_KEY ? "created" : "opened", hKey);

    /* Step 2: Set a string value */
    UNICODE_STRING valueName;
    valueName.Buffer = L"TestValue";
    valueName.Length = (USHORT)(wcslen(valueName.Buffer) * sizeof(WCHAR));
    valueName.MaximumLength = valueName.Length + sizeof(WCHAR);

    WCHAR valueData[] = L"SysWhispers4 was here";
    ULONG dataSize = (ULONG)(sizeof(valueData));

    printf("[*] Setting value: TestValue = \"%ls\"\n", valueData);
    status = SW4_NtSetValueKey(
        hKey,
        &valueName,
        0,
        REG_SZ,
        valueData,
        dataSize
    );
    if (!NT_SUCCESS(status)) {
        printf("[-] NtSetValueKey failed: 0x%08X\n", (unsigned int)status);
        SW4_NtClose(hKey);
        return 1;
    }
    printf("[+] Value set successfully\n");

    /* Step 3: Query the value back */
    BYTE queryBuf[256];
    ULONG resultLen = 0;

    printf("[*] Querying value back...\n");
    status = SW4_NtQueryValueKey(
        hKey,
        &valueName,
        KeyValuePartialInformation,
        queryBuf,
        sizeof(queryBuf),
        &resultLen
    );
    if (NT_SUCCESS(status)) {
        /* KeyValuePartialInformation: offset 0xC = Data */
        WCHAR *readBack = (WCHAR *)(queryBuf + 12);
        printf("[+] Read back: \"%ls\" (%lu bytes)\n", readBack, resultLen);
    } else {
        printf("[-] NtQueryValueKey failed: 0x%08X\n", (unsigned int)status);
    }

    /* Step 4: Clean up -- delete key and close */
    printf("[*] Deleting test key...\n");
    status = SW4_NtDeleteKey(hKey);
    if (NT_SUCCESS(status)) {
        printf("[+] Key deleted\n");
    } else {
        printf("[-] NtDeleteKey failed: 0x%08X (may need elevated privileges)\n",
            (unsigned int)status);
    }

    SW4_NtClose(hKey);
    printf("[+] Done.\n");
    return 0;
}
