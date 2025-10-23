# Mimikatz Modernization Plan for Windows 11 25H2

## Project Overview

Comprehensive modernization of mimikatz for Windows 11 25H2 (Build 27723+) with focus on bypassing modern security mitigations including LSA Protection (PPL), Credential Guard, and enhanced EDR detection.

## Current Architecture Analysis

### Core Components

**1. Main Executable (`mimikatz/`)**
- Entry point and command dispatcher
- Module orchestration
- Interactive CLI interface

**2. Sekurlsa Module (`mimikatz/modules/sekurlsa/`)**
- Primary credential dumping engine
- Packages for different providers:
  - `msv1_0` - LM/NTLM hashes
  - `wdigest` - Cleartext passwords
  - `kerberos` - Kerberos tickets/keys
  - `tspkg` - Terminal Server credentials
  - `cloudap` - Azure AD credentials
  - `ssp` - SSP credentials
  - `livessp` - LiveSSP credentials
  - `credman` - Credential Manager

**3. Crypto Module** - DPAPI, certificates, keys
**4. Lsadump Module** - SAM/SECRETS/CACHE dumping, DCSync
**5. Kernel Module (`mimidrv/`)** - Kernel driver for low-level operations
**6. Supporting Modules** - Token manipulation, process injection, misc utilities

### Memory Access Strategy

Current mimikatz uses two primary methods:
1. **User-mode process attach**: `OpenProcess()` + `ReadProcessMemory()` on LSASS
2. **Minidump parsing**: Offline analysis of LSASS dump files

## Windows 11 25H2 Challenges

### 1. LSA Protection (PPL - Protected Process Light)

**Problem**: LSASS runs as protected process, user-mode `OpenProcess()` fails
**Impact**: Cannot attach to LSASS from user-mode
**Current Status**: Requires SeDebugPrivilege + PPL bypass

**Solutions**:
- Kernel driver with `PsIsProtectedProcess` bypass
- Vulnerable driver exploitation (BYOVD)
- PPL bypass via process tampering

### 2. Credential Guard

**Problem**: Credentials isolated in Isolated User Mode (VTL1)
**Impact**: Credentials not accessible from normal kernel space
**Current Status**: Requires VTL0→VTL1 exploit or bootkey extraction

**Solutions**:
- SecureKernel boot key extraction
- VBS/HVCI bypass techniques
- Attack Credential Manager instead

###

 3. Enhanced Structure Obfuscation

**Problem**: Microsoft randomizes LSASS internal structures per build
**Impact**: Hardcoded offsets break on updates
**Current Status**: Requires pattern scanning or symbol resolution

**Solutions**:
- Dynamic pattern matching
- PDB symbol parsing at runtime
- Machine learning-based structure fingerprinting

### 4. EDR Detection

**Problem**: Modern EDRs detect mimikatz signatures
**Impact**: Immediate detection and blocking
**Current Status**: Heavy signatured, easily detected

**Solutions**:
- Code obfuscation
- API unhooking
- Direct syscalls
- Stealth memory access via driver

### 5. Microsoft Vulnerable Driver Blocklist

**Problem**: Known vulnerable drivers blocked by hvci.sys
**Impact**: Cannot load well-known BYOVD drivers
**Current Status**: Blocklist updated to 10.0.27825.0+

**Solutions**:
- Find new vulnerable drivers (driver-hunter project)
- CIM-based memory loading (signature flipping)
- Registry confusion techniques
- Custom driver signing (expired certs)

## Modernization Strategy

### Phase 1: Analysis & Documentation (CURRENT)

**Objectives**:
- Map current codebase architecture
- Identify Windows 11 25H2 specific issues
- Document LSASS internal structures for latest builds
- Create comprehensive build system

**Deliverables**:
- Architecture documentation
- Build guide for modern Visual Studio
- Windows 11 25H2 structure definitions
- Git repository with version control

### Phase 2: Core Modernization

**Objectives**:
- Update structure definitions for Windows 11 25H2
- Implement dynamic offset resolution
- Add PPL detection and bypass framework
- Modernize build system

**Tasks**:
1. Extract and document LSASS structures for:
   - Windows 11 22H2 (Build 22621)
   - Windows 11 23H2 (Build 22631)
   - Windows 11 25H2 (Build 27723+)

2. Implement pattern-based structure scanning:
   - LogonSessionList location
   - Key encryption routines (LsaProtectMemory/LsaUnprotectMemory)
   - Package-specific credential structures

3. Add PPL bypass framework:
   - PPL detection routine
   - Driver communication interface
   - Fallback to minidump mode if PPL active

4. Build system updates:
   - Support Visual Studio 2022
   - Add CMake build option
   - Automated testing framework

### Phase 3: Driver Integration

**Objectives**:
- Integrate vulnerable driver exploitation
- Implement kernel-mode memory access
- Create stealth loading mechanisms

**Tasks**:
1. **Driver Hunter Integration**:
   - Import driver-hunter scanning results
   - Automated vulnerable driver selection
   - Capability matching (Tool-Alpha requirements)

2. **BYOVD Framework**:
   - Generic driver exploitation template
   - IOCTL fuzzing for memory R/W primitives
   - Support for multiple driver backends

3. **Stealth Loading**:
   - CIM-based driver loading
   - Per-system signature flipping
   - Registry confusion implementation
   - In-memory PE loading

4. **Memory Access via Driver**:
   - Kernel-mode LSASS memory reading
   - Physical memory mapping
   - CR3 manipulation for address translation

### Phase 4: Advanced Bypasses

**Objectives**:
- Credential Guard bypass
- Anti-EDR techniques
- Stealth improvements

**Tasks**:
1. **Credential Guard Bypass**:
   - SecureKernel boot key extraction
   - LSA Isolated credentials decryption
   - Alternative credential sources (Credential Manager, NGC)

2. **EDR Evasion**:
   - API unhooking (manual syscalls)
   - ETW blind spotting
   - Process hollowing / module stomping
   - Obfuscation and packing

3. **Detection Resistance**:
   - Remove known IOCs
   - Randomize strings and artifacts
   - Polymorphic code generation
   - Clean memory footprint

### Phase 5: Testing & Validation

**Objectives**:
- Comprehensive testing on Windows 11 25H2
- Validation against modern EDRs
- Performance optimization

**Tasks**:
1. **Test Environment Setup**:
   - Windows 11 25H2 VMs (multiple builds)
   - Various protection configurations:
     - LSA Protection enabled/disabled
     - Credential Guard enabled/disabled
     - HVCI enabled/disabled
     - Various EDR solutions

2. **Functional Testing**:
   - Credential extraction success rate
   - PPL bypass reliability
   - Driver loading success
   - False positive rate

3. **Stealth Testing**:
   - EDR detection rate
   - Event log analysis
   - Network traffic analysis
   - Forensic footprint assessment

## Technical Implementation Details

### Dynamic Structure Resolution

**Current Approach**: Hardcoded offsets in `globals_sekurlsa.h`
**New Approach**: Runtime pattern scanning

```c
// Pattern-based LogonSessionList location
typedef struct _SEKURLSA_PATTERN {
    BYTE pattern[32];
    BYTE mask[32];
    LONG offset;
    CHAR *description;
} SEKURLSA_PATTERN;

// Windows 11 25H2 specific patterns
SEKURLSA_PATTERN Win11_25H2_Patterns[] = {
    // LogonSessionList search pattern
    {
        {0x48, 0x8B, 0x0D, 0x??, 0x??, 0x??, 0x??, 0x48, 0x85, 0xC9},
        {0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF},
        3,
        "LogonSessionList"
    },
    // LsaProtectMemory pattern
    // ...
};
```

### Driver-Based Memory Access

**Integration with driver-hunter**:
```c
typedef struct _DRIVER_MEMORY_INTERFACE {
    HANDLE hDriver;
    ULONG ioctlReadMemory;
    ULONG ioctlWriteMemory;
    BOOL (*ReadKernelMemory)(PVOID source, PVOID dest, SIZE_T size);
    BOOL (*WriteKernelMemory)(PVOID dest, PVOID source, SIZE_T size);
} DRIVER_MEMORY_INTERFACE;

// Auto-select vulnerable driver based on system
NTSTATUS InitializeDriverInterface(DRIVER_MEMORY_INTERFACE *pDrvInterface) {
    // Query driver-hunter database for compatible driver
    // Load driver with stealth techniques
    // Initialize IOCTL interface
    // Return success/failure
}
```

### PPL Bypass Framework

```c
typedef enum _SEKURLSA_ACCESS_METHOD {
    SEKURLSA_ACCESS_USERMODE,      // Standard OpenProcess
    SEKURLSA_ACCESS_DRIVER,         // Via vulnerable driver
    SEKURLSA_ACCESS_MINIDUMP,       // Offline dump analysis
    SEKURLSA_ACCESS_KERNEL_SHELLCODE  // Direct kernel shellcode
} SEKURLSA_ACCESS_METHOD;

NTSTATUS SelectAccessMethod(SEKURLSA_ACCESS_METHOD *method) {
    if (IsLsaProtectionEnabled()) {
        if (DriverAvailable()) {
            *method = SEKURLSA_ACCESS_DRIVER;
        } else {
            *method = SEKURLSA_ACCESS_MINIDUMP;
            kprintf(L"[!] PPL enabled but no driver available. Use minidump mode.\n");
        }
    } else {
        *method = SEKURLSA_ACCESS_USERMODE;
    }
    return STATUS_SUCCESS;
}
```

## Build System Requirements

### Prerequisites
- Visual Studio 2022 (Community Edition or higher)
- Windows SDK 10.0.22621.0 or later
- Windows Driver Kit (WDK) 10.0.22621.0 (for driver compilation)
- Git for version control
- Python 3.10+ (for build automation)

### Optional
- CMake 3.20+ (alternative build system)
- LLVM/Clang (for additional obfuscation)

### Compile Commands

**Standard Build:**
```cmd
msbuild mimikatz.sln /p:Configuration=Release /p:Platform=x64
```

**With Obfuscation:**
```cmd
msbuild mimikatz.sln /p:Configuration=Release /p:Platform=x64 /p:Obfuscate=true
```

**CMake Build:**
```cmd
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

## Integration with Driver-Hunter

### Automated Driver Selection

The driver-hunter project provides:
1. Database of vulnerable drivers with capability scores
2. Tool-Alpha score (credential dumping capability)
3. Tool-Beta score (advanced manipulation)
4. Automated scanning and validation

**Integration Flow**:
```
1. Query driver-hunter database for high Tool-Alpha score drivers
2. Filter by Windows 11 25H2 compatibility
3. Check against Microsoft blocklist
4. Select driver with best stealth/capability ratio
5. Load driver using CIM or registry confusion
6. Initialize memory interface
7. Proceed with credential dumping
```

### Driver Database Schema

```sql
SELECT filename, sha256, vulnerability_type, tool_alpha_score
FROM drivers
WHERE vulnerable = 1
AND tool_alpha_score >= 20
AND (vulnerability_type LIKE '%MEMORY_ACCESS%'
     OR vulnerability_type LIKE '%CREDENTIAL_DUMPING%')
ORDER BY tool_alpha_score DESC
LIMIT 10;
```

## Documentation Structure

### Files to Create

1. `BUILD.md` - Comprehensive build guide
2. `ARCHITECTURE.md` - System architecture documentation
3. `STRUCTURES.md` - Windows 11 structure definitions
4. `DRIVER_INTEGRATION.md` - Driver exploitation guide
5. `TESTING.md` - Test procedures and validation
6. `CHANGELOG.md` - Version history and updates

## Version Control Strategy

### Branching Strategy

- `master` - Stable releases only
- `develop` - Active development branch
- `feature/*` - Feature-specific branches
- `windows11-25h2` - Windows 11 25H2 specific work

### Commit Guidelines

- Prefix commits with module: `[sekurlsa]`, `[driver]`, `[build]`, etc.
- Reference issue numbers when applicable
- Sign commits with GPG key
- Automated testing before merge

### Tagging

- `v3.0.0-alpha` - Initial Windows 11 25H2 support
- `v3.0.0-beta` - Feature complete, testing phase
- `v3.0.0-rc1` - Release candidate
- `v3.0.0` - Stable release

## Security Considerations

### Legal and Ethical Use

- Educational and research purposes only
- Authorized penetration testing with written permission
- Lab environments for defensive security research
- Responsible disclosure of new techniques

### Operational Security

- Never use on production systems without authorization
- Clean up artifacts after testing
- Encrypt communication channels
- Secure development environment

## Success Criteria

### Minimum Viable Product (MVP)

- [ ] Successfully extract credentials from Windows 11 25H2 with PPL enabled
- [ ] Dynamic structure resolution (no hardcoded offsets)
- [ ] Driver-based memory access functional
- [ ] Passes basic EDR evasion tests
- [ ] Comprehensive documentation

### Full Release Criteria

- [ ] All credential providers functional (msv, wdigest, kerberos, cloudap)
- [ ] Credential Guard bypass working
- [ ] Multiple driver backends supported
- [ ] Advanced EDR evasion techniques
- [ ] Automated testing suite
- [ ] Public release with full documentation

## Timeline Estimate

- **Phase 1** (Analysis): 1-2 weeks (CURRENT)
- **Phase 2** (Core Modernization): 3-4 weeks
- **Phase 3** (Driver Integration): 2-3 weeks
- **Phase 4** (Advanced Bypasses): 3-4 weeks
- **Phase 5** (Testing): 2-3 weeks

**Total**: 11-16 weeks for full implementation

## Resources and References

### Microsoft Documentation
- [Protected Process Light (PPL)](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-)
- [Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)
- [HVCI and VBS](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-hvci-enablement)
- [Driver Blocklist](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules)

### Research Papers
- "Bypassing LSA Protection in Windows 8.1" - James Forshaw
- "Accessing LSASS Memory on Windows 10" - Clément Labro
- "Credential Guard Bypass Techniques" - Various authors
- "BYOVD: Bring Your Own Vulnerable Driver" - Red Team Research

### Related Projects
- **driver-hunter**: Automated vulnerable driver discovery (local project)
- **mimikatz**: Original implementation by gentilkiwi
- **PPLdump**: PPL bypass tool
- **nanodump**: Stealth LSASS dumping
- **KernelKatz / KernelTool**: Kernel-mode credential dumping (reference implementation)

## Contact and Contribution

**Author**: Will Burns (Volume19)
**Email**: willburns89@gmail.com
**GitHub**: https://github.com/volume19

For authorized security research and lab testing only.

---

**Last Updated**: 2025-10-22
**Current Phase**: Phase 1 - Analysis & Documentation
