# openHiTLS Dependency Configuration Guide

This document describes how to configure openHiTLS dependencies for the SDFX project using the pure CMake dependency discovery system.

## Overview

The SDFX build system supports multiple methods to locate and configure openHiTLS dependencies:

1. **Auto-detection** (default - pure CMake)
2. **Environment variables**
3. **CMake variables**
4. **pkg-config**
5. **System paths**

## Verified CryptoKit build profile

The repository Dockerfile builds the bundled openHiTLS source first and installs it to `/opt/openhitls`. SDFX is then configured with an explicit root and TCP transport:

```bash
cmake -S /src/sdfx -B /build/sdfx -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/opt/sdfx \
  -DOpenHiTLS_ROOT_DIR=/opt/openhitls \
  -DSDFX_TRANSPORT_TYPE=tcp \
  -DBUILD_TESTS=ON
```

This is the release-tested configuration for the Linux daemon and Windows TCP SDK. The source CMake default transport is `unix`; do not omit the explicit TCP option when reproducing the container build. The Windows client DLL does not link openHiTLS because all cryptographic operations run in the Linux daemon.

The bundled openHiTLS header currently identifies the source as `openHiTLS 0.4.0 31 Mar. 2026`. The exact upstream snapshot and redistribution notices are tracked in [`../../THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md).

## Configuration Methods

### 1. Auto-Detection (Recommended)

The build system automatically detects openHiTLS installation using pure CMake:

```bash
# Clean build with auto-detection
rm -rf build && mkdir build && cd build
cmake ..
make
```

Auto-detection searches in the following order:
- CMake variable `OpenHiTLS_ROOT_DIR`
- `$OPENHITLS_ROOT` environment variable
- pkg-config (if enabled)
- `/usr/local`
- `/usr`
- `/opt/local` 
- `/opt/openhitls`
- `/opt`
- `../openhitls_install` (backward compatibility)

### 2. Environment Variable

Set the `OPENHITLS_ROOT` environment variable:

```bash
export OPENHITLS_ROOT=/path/to/openhitls
cmake ..
make
```

### 3. CMake Variable

Specify the path directly to CMake:

```bash
cmake -DOpenHiTLS_ROOT_DIR=/path/to/openhitls ..
make
```

### 4. pkg-config (System Installation)

For system-wide installations using pkg-config:

```bash
# Install openHiTLS system-wide first, then:
cmake -DOPENHITLS_USE_PKGCONFIG=ON ..
make
```

### 5. Disable pkg-config

To disable pkg-config and use only manual configuration:

```bash
cmake -DOPENHITLS_USE_PKGCONFIG=OFF -DOpenHiTLS_ROOT_DIR=/custom/path ..
make
```

## Build Configuration Options

### openHiTLS Detection Options

- `OpenHiTLS_ROOT_DIR`: Explicit path to openHiTLS installation
- `OPENHITLS_USE_PKGCONFIG`: Use pkg-config for discovery (default: ON)

### Example Build Commands

```bash
# Basic auto-detection build
mkdir build && cd build
cmake ..
make

# Custom path build
mkdir build && cd build  
cmake -DOpenHiTLS_ROOT_DIR=/opt/openhitls ..
make

# Development build with custom path
mkdir build_dev && cd build_dev
cmake -DCMAKE_BUILD_TYPE=Debug -DOpenHiTLS_ROOT_DIR=/home/user/openhitls_dev ..
make

# System installation build
mkdir build_system && cd build_system
cmake -DOPENHITLS_USE_PKGCONFIG=ON ..
make
```

## Installation Directory Structure

openHiTLS installation should follow this structure:

```
/path/to/openhitls/
├── include/
│   └── hitls/
│       ├── crypto/
│       │   ├── crypt_eal_cipher.h
│       │   └── ...
│       ├── bsl/
│       │   ├── bsl_log.h
│       │   └── ...
│       ├── tls/
│       ├── pki/
│       └── auth/
└── lib/
    ├── libhitls_crypto.so (or .a)
    ├── libhitls_bsl.so (or .a)
    ├── libhitls_tls.so (optional)
    ├── libhitls_pki.so (optional)
    ├── libhitls_auth.so (optional)
    └── libboundscheck.so (optional)
```

## Verification

### CMake Configuration Check

After running cmake, check the configuration output:

```
-- Found OpenHiTLS: /path/to/openhitls/include (found version "unknown")
-- Found openHiTLS unknown
--   Include dir: /path/to/openhitls/include
--   Root dir: /path/to/openhitls
--   Libraries: /path/to/openhitls/lib/libhitls_crypto.so;/path/to/openhitls/lib/libhitls_bsl.so;...

-- SDFX Configuration:
--   Version: 1.1.3
--   Build type: Release
--   C Compiler: /usr/bin/cc
--   Install prefix: /usr/local
--   openHiTLS root: /path/to/openhitls
--   openHiTLS version: unknown
--   Transport type: unix

-- Found openHiTLS libraries:
--   libhitls_crypto: /path/to/openhitls/lib/libhitls_crypto.so
--   libhitls_bsl: /path/to/openhitls/lib/libhitls_bsl.so
--   libboundscheck: not found (optional)
```

## Troubleshooting

### 1. "Could not find OpenHiTLS" error

```bash
# Check if the path exists and has correct structure
ls -la /path/to/openhitls/{include,lib}

# Try manual path specification  
cmake -DOpenHiTLS_ROOT_DIR=/correct/path ..
```

### 2. Library linking errors

```bash
# Check library permissions and architecture
file /path/to/openhitls/lib/libhitls_*.so
ldd /path/to/openhitls/lib/libhitls_crypto.so

# Set runtime library path
export LD_LIBRARY_PATH=/path/to/openhitls/lib:$LD_LIBRARY_PATH
```

### 3. Header file not found

```bash
# Verify header structure
find /path/to/openhitls/include -name "*.h" | head -10

# Check specific required headers
ls -la /path/to/openhitls/include/hitls/crypto/crypt_eal_cipher.h
ls -la /path/to/openhitls/include/hitls/bsl/bsl_log.h
```

### 4. Version mismatch

```bash
# Check actual version in headers
grep -r "VERSION\|version" /path/to/openhitls/include/hitls/ | head -5

# Force specific version requirements
cmake -DOpenHiTLS_FIND_VERSION="1.0.0" ..
```

## Migration from Old Build System

### For existing projects using hardcoded paths:

**Old method:**
```bash
# Fixed path - not flexible
cmake ..  # Always uses ../openhitls_install
```

**New method:**
```bash
# Flexible path detection - pure CMake
cmake ..                                           # Auto-detect
# OR
cmake -DOpenHiTLS_ROOT_DIR=/your/custom/path ..    # Custom path
# OR  
export OPENHITLS_ROOT=/your/custom/path && cmake .. # Environment variable
```

### Backward Compatibility

The new system maintains backward compatibility:
- If `../openhitls_install` exists, it will be detected automatically
- No changes needed for existing build scripts
- Pure CMake implementation - no external dependencies

## Development Workflow

### For openHiTLS developers:

```bash
# Use development build of openHiTLS
export OPENHITLS_ROOT=/home/dev/openhitls_debug
mkdir build_dev && cd build_dev
cmake -DCMAKE_BUILD_TYPE=Debug ..
make

# Switch to release build  
export OPENHITLS_ROOT=/usr/local
mkdir build_release && cd build_release  
cmake -DCMAKE_BUILD_TYPE=Release ..
make
```

### For CI/CD pipelines:

```bash
# Predictable system installation
cmake -DOPENHITLS_USE_PKGCONFIG=ON ..

# OR explicit path for controlled environments
cmake -DOpenHiTLS_ROOT_DIR="${OPENHITLS_INSTALL_PREFIX}" ..
```

## Advantages of Pure CMake Implementation

- ✅ **No external dependencies** - Only requires CMake
- ✅ **Cross-platform compatibility** - Works on Windows, macOS, Linux
- ✅ **Simpler build system** - No shell script execution
- ✅ **Better error reporting** - CMake provides detailed diagnostics
- ✅ **IDE integration** - Full support for Visual Studio, CLion, etc.
- ✅ **Faster configuration** - Native CMake performance
## Distribution licensing

CryptoKit SoftHSM original additions and modifications are distributed under
GNU AGPL v3.0 only (`AGPL-3.0-only`) from
<https://github.com/sawanolin/cryptokit-soft-hsm>. Bundled openHiTLS and SDFX
material retains its existing Mulan PSL v2 notices and license copies. See
[`../../THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md) before creating
source, image, or SDK distributions.

