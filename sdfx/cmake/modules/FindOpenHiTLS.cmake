# FindOpenHiTLS.cmake
# Find the openHiTLS cryptographic library
#
# This module defines:
#  OpenHiTLS_FOUND         - TRUE if openHiTLS is found
#  OpenHiTLS_INCLUDE_DIRS  - Include directories for openHiTLS
#  OpenHiTLS_LIBRARIES     - Libraries to link against
#  OpenHiTLS_VERSION       - Version string
#  OpenHiTLS_ROOT_DIR      - Root directory of openHiTLS installation
#
# The following cache variables are also set:
#  OpenHiTLS_CRYPTO_LIBRARY - Path to libhitls_crypto
#  OpenHiTLS_BSL_LIBRARY    - Path to libhitls_bsl  
#  OpenHiTLS_TLS_LIBRARY    - Path to libhitls_tls (optional)
#  OpenHiTLS_PKI_LIBRARY    - Path to libhitls_pki (optional)
#  OpenHiTLS_AUTH_LIBRARY   - Path to libhitls_auth (optional)
#  OpenHiTLS_BOUNDSCHECK_LIBRARY - Path to libboundscheck (optional)
#
# You can set the following variables to help guide the search:
#  OPENHITLS_ROOT        - Environment variable or CMake variable
#  OpenHiTLS_ROOT_DIR    - CMake variable (preferred)
#

# Use pkg-config if available
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(PC_OpenHiTLS QUIET openhitls)
endif()

# Determine search paths in priority order
set(_search_paths)

# 1. CMake variable (highest priority)
if(OpenHiTLS_ROOT_DIR)
    list(APPEND _search_paths "${OpenHiTLS_ROOT_DIR}")
endif()

# 2. Environment variable
if(DEFINED ENV{OPENHITLS_ROOT})
    list(APPEND _search_paths "$ENV{OPENHITLS_ROOT}")
endif()

# 3. pkg-config paths
if(PC_OpenHiTLS_PREFIX)
    list(APPEND _search_paths "${PC_OpenHiTLS_PREFIX}")
endif()

# 4. Standard system paths
list(APPEND _search_paths
    /usr/local
    /usr
    /opt/local
    /opt/openhitls
    /opt
)

# 5. Relative path fallback (backward compatibility)
get_filename_component(_project_dir "${CMAKE_CURRENT_SOURCE_DIR}" DIRECTORY)
set(_relative_path "${_project_dir}/openhitls_install")
if(EXISTS "${_relative_path}")
    list(APPEND _search_paths "${_relative_path}")
endif()

# Find include directory
find_path(OpenHiTLS_INCLUDE_DIR
    NAMES hitls/crypto/crypt_eal_cipher.h
          hitls/bsl/bsl_log.h
    PATHS ${_search_paths}
    PATH_SUFFIXES include
    DOC "openHiTLS include directory"
)

# Find required libraries
find_library(OpenHiTLS_CRYPTO_LIBRARY
    NAMES hitls_crypto libhitls_crypto
    PATHS ${_search_paths}
    PATH_SUFFIXES lib lib64 lib32
    DOC "openHiTLS crypto library"
)

find_library(OpenHiTLS_BSL_LIBRARY
    NAMES hitls_bsl libhitls_bsl
    PATHS ${_search_paths}
    PATH_SUFFIXES lib lib64 lib32
    DOC "openHiTLS BSL library"
)

# Find optional libraries
find_library(OpenHiTLS_TLS_LIBRARY
    NAMES hitls_tls libhitls_tls
    PATHS ${_search_paths}
    PATH_SUFFIXES lib lib64 lib32
    DOC "openHiTLS TLS library"
)

find_library(OpenHiTLS_PKI_LIBRARY
    NAMES hitls_pki libhitls_pki
    PATHS ${_search_paths}
    PATH_SUFFIXES lib lib64 lib32
    DOC "openHiTLS PKI library"
)

find_library(OpenHiTLS_AUTH_LIBRARY
    NAMES hitls_auth libhitls_auth
    PATHS ${_search_paths}
    PATH_SUFFIXES lib lib64 lib32
    DOC "openHiTLS Auth library"
)

find_library(OpenHiTLS_BOUNDSCHECK_LIBRARY
    NAMES boundscheck libboundscheck
    PATHS ${_search_paths}
    PATH_SUFFIXES lib lib64 lib32
    DOC "BoundsCheck library"
)

# Determine root directory
if(OpenHiTLS_INCLUDE_DIR)
    get_filename_component(_include_parent "${OpenHiTLS_INCLUDE_DIR}" DIRECTORY)
    set(OpenHiTLS_ROOT_DIR "${_include_parent}" CACHE PATH "openHiTLS root directory")
endif()

# Extract version information
if(OpenHiTLS_INCLUDE_DIR AND EXISTS "${OpenHiTLS_INCLUDE_DIR}/hitls/bsl/bsl_sal.h")
    file(STRINGS "${OpenHiTLS_INCLUDE_DIR}/hitls/bsl/bsl_sal.h" _version_line
         REGEX "^#define[ \t]+HITLS_VERSION[ \t]+")
    if(_version_line)
        string(REGEX REPLACE "^#define[ \t]+HITLS_VERSION[ \t]+\"([^\"]+)\".*" "\\1"
               OpenHiTLS_VERSION "${_version_line}")
    endif()
endif()

# Set version to unknown if not found
if(NOT OpenHiTLS_VERSION)
    set(OpenHiTLS_VERSION "unknown")
endif()

# Assemble libraries list
set(OpenHiTLS_LIBRARIES)
if(OpenHiTLS_CRYPTO_LIBRARY)
    list(APPEND OpenHiTLS_LIBRARIES ${OpenHiTLS_CRYPTO_LIBRARY})
endif()
if(OpenHiTLS_BSL_LIBRARY)
    list(APPEND OpenHiTLS_LIBRARIES ${OpenHiTLS_BSL_LIBRARY})
endif()
if(OpenHiTLS_TLS_LIBRARY)
    list(APPEND OpenHiTLS_LIBRARIES ${OpenHiTLS_TLS_LIBRARY})
endif()
if(OpenHiTLS_PKI_LIBRARY)
    list(APPEND OpenHiTLS_LIBRARIES ${OpenHiTLS_PKI_LIBRARY})
endif()
if(OpenHiTLS_AUTH_LIBRARY)
    list(APPEND OpenHiTLS_LIBRARIES ${OpenHiTLS_AUTH_LIBRARY})
endif()
if(OpenHiTLS_BOUNDSCHECK_LIBRARY)
    list(APPEND OpenHiTLS_LIBRARIES ${OpenHiTLS_BOUNDSCHECK_LIBRARY})
endif()

# Set include directories
set(OpenHiTLS_INCLUDE_DIRS ${OpenHiTLS_INCLUDE_DIR})

# Handle find_package arguments and set OpenHiTLS_FOUND
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(OpenHiTLS
    REQUIRED_VARS
        OpenHiTLS_INCLUDE_DIR
        OpenHiTLS_CRYPTO_LIBRARY
        OpenHiTLS_BSL_LIBRARY
    VERSION_VAR OpenHiTLS_VERSION
    HANDLE_COMPONENTS
)

# Create imported targets
if(OpenHiTLS_FOUND AND NOT TARGET OpenHiTLS::crypto)
    add_library(OpenHiTLS::crypto UNKNOWN IMPORTED)
    set_target_properties(OpenHiTLS::crypto PROPERTIES
        IMPORTED_LOCATION "${OpenHiTLS_CRYPTO_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${OpenHiTLS_INCLUDE_DIRS};${OpenHiTLS_INCLUDE_DIR}/hitls"
    )
    
    add_library(OpenHiTLS::bsl UNKNOWN IMPORTED)
    set_target_properties(OpenHiTLS::bsl PROPERTIES
        IMPORTED_LOCATION "${OpenHiTLS_BSL_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${OpenHiTLS_INCLUDE_DIRS};${OpenHiTLS_INCLUDE_DIR}/hitls"
    )
    
    # Optional components
    if(OpenHiTLS_TLS_LIBRARY)
        add_library(OpenHiTLS::tls UNKNOWN IMPORTED)
        set_target_properties(OpenHiTLS::tls PROPERTIES
            IMPORTED_LOCATION "${OpenHiTLS_TLS_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${OpenHiTLS_INCLUDE_DIRS};${OpenHiTLS_INCLUDE_DIR}/hitls"
        )
    endif()
    
    if(OpenHiTLS_PKI_LIBRARY)
        add_library(OpenHiTLS::pki UNKNOWN IMPORTED)
        set_target_properties(OpenHiTLS::pki PROPERTIES
            IMPORTED_LOCATION "${OpenHiTLS_PKI_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${OpenHiTLS_INCLUDE_DIRS};${OpenHiTLS_INCLUDE_DIR}/hitls"
        )
    endif()
    
    if(OpenHiTLS_AUTH_LIBRARY)
        add_library(OpenHiTLS::auth UNKNOWN IMPORTED)
        set_target_properties(OpenHiTLS::auth PROPERTIES
            IMPORTED_LOCATION "${OpenHiTLS_AUTH_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${OpenHiTLS_INCLUDE_DIRS};${OpenHiTLS_INCLUDE_DIR}/hitls"
        )
    endif()
    
    if(OpenHiTLS_BOUNDSCHECK_LIBRARY)
        add_library(OpenHiTLS::boundscheck UNKNOWN IMPORTED)
        set_target_properties(OpenHiTLS::boundscheck PROPERTIES
            IMPORTED_LOCATION "${OpenHiTLS_BOUNDSCHECK_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${OpenHiTLS_INCLUDE_DIRS};${OpenHiTLS_INCLUDE_DIR}/hitls"
        )
    endif()
    
    # Convenience target with all required libraries
    add_library(OpenHiTLS::OpenHiTLS INTERFACE IMPORTED)
    target_link_libraries(OpenHiTLS::OpenHiTLS INTERFACE
        OpenHiTLS::crypto
        OpenHiTLS::bsl
    )
    if(TARGET OpenHiTLS::boundscheck)
        target_link_libraries(OpenHiTLS::OpenHiTLS INTERFACE OpenHiTLS::boundscheck)
    endif()
endif()

# Mark cache variables as advanced
mark_as_advanced(
    OpenHiTLS_INCLUDE_DIR
    OpenHiTLS_CRYPTO_LIBRARY
    OpenHiTLS_BSL_LIBRARY
    OpenHiTLS_TLS_LIBRARY
    OpenHiTLS_PKI_LIBRARY
    OpenHiTLS_AUTH_LIBRARY
    OpenHiTLS_BOUNDSCHECK_LIBRARY
)

# Debug information
if(OpenHiTLS_FOUND)
    message(STATUS "Found openHiTLS ${OpenHiTLS_VERSION}")
    message(STATUS "  Include dir: ${OpenHiTLS_INCLUDE_DIR}")
    message(STATUS "  Root dir: ${OpenHiTLS_ROOT_DIR}")
    message(STATUS "  Libraries: ${OpenHiTLS_LIBRARIES}")
endif()
