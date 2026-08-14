cmake_minimum_required(VERSION 3.16)

project(sdfx 
    VERSION 1.1.3
    DESCRIPTION "SDFX - Software SDF Implementation based on GM/T 0018-2023"
    LANGUAGES C
)

# Define standard install directories before any subdirectory uses them.
include(GNUInstallDirs)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compilation options
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Set compiler flags
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -Wall -Wextra -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")

# Options
option(BUILD_DAEMON "Build sdfxd daemon" ON)
option(BUILD_SDK "Build libsdfx.so SDK" ON)
option(BUILD_CLI "Build sdfx-cli tool" OFF)  # Temporarily disabled
option(BUILD_TESTS "Build test programs" ON)
option(BUILD_EXAMPLES "Build example programs" ON)

# Transport layer options
set(SDFX_TRANSPORT_TYPE "unix" CACHE STRING "Transport type: unix, tcp, shm, or custom")
set_property(CACHE SDFX_TRANSPORT_TYPE PROPERTY STRINGS "unix" "tcp" "shm" "custom")

# Custom transport library path (only used when SDFX_TRANSPORT_TYPE is custom)
set(CUSTOM_TRANSPORT_LIB_PATH "" CACHE STRING "Path to custom transport library (.so file)")

# Add our custom modules path
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

# openHiTLS dependency configuration
set(OpenHiTLS_ROOT_DIR "" CACHE PATH "Path to openHiTLS installation")
option(OPENHITLS_USE_PKGCONFIG "Use pkg-config to find openHiTLS" ON)

if(WIN32)
    # winpthread is linked statically into the SDK DLL below so the binary package
    # contains only sdfapi_x64.dll.
    set(COMMON_LIBS ws2_32)
else()
    find_package(OpenHiTLS REQUIRED)
    include_directories(
        ${OpenHiTLS_INCLUDE_DIRS}
        ${OpenHiTLS_INCLUDE_DIR}/hitls
        ${OpenHiTLS_INCLUDE_DIR}/hitls/bsl
        ${OpenHiTLS_INCLUDE_DIR}/hitls/crypto
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    set(COMMON_LIBS OpenHiTLS::OpenHiTLS -lm -lpthread)
endif()

# Transport layer configuration definitions
if(SDFX_TRANSPORT_TYPE STREQUAL "tcp")
    add_definitions(-DSDFX_TRANSPORT_TCP)
    message(STATUS "Using TCP transport")
elseif(SDFX_TRANSPORT_TYPE STREQUAL "unix")
    add_definitions(-DSDFX_TRANSPORT_UNIX)
    message(STATUS "Using Unix Domain Socket transport")
elseif(SDFX_TRANSPORT_TYPE STREQUAL "shm")
    add_definitions(-DSDFX_TRANSPORT_SHM)
    message(STATUS "Using Shared Memory transport")
elseif(SDFX_TRANSPORT_TYPE STREQUAL "custom")
    add_definitions(-DSDFX_TRANSPORT_CUSTOM)
    if(NOT CUSTOM_TRANSPORT_LIB_PATH)
        message(FATAL_ERROR "CUSTOM_TRANSPORT_LIB_PATH must be specified when using custom transport")
    endif()
    add_definitions(-DCUSTOM_TRANSPORT_LIB_PATH="${CUSTOM_TRANSPORT_LIB_PATH}")
    message(STATUS "Using Custom transport library: ${CUSTOM_TRANSPORT_LIB_PATH}")
    # Add dlopen library
    list(APPEND COMMON_LIBS -ldl)
else()
    message(FATAL_ERROR "Invalid SDFX_TRANSPORT_TYPE: ${SDFX_TRANSPORT_TYPE}. Valid values: unix, tcp, shm, custom")
endif()

# Include public headers
add_subdirectory(include)

# Include server-side common modules only where openHiTLS is available.
if(NOT WIN32)
    add_subdirectory(common)
endif()

# Build transport layer
add_subdirectory(transport)

# Build components
if(BUILD_SDK)
    add_subdirectory(sdk)
endif()

if(BUILD_DAEMON)
    add_subdirectory(sdfxd)
endif()

if(BUILD_CLI)
    add_subdirectory(cli)
endif()

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Installation configuration
# GNUInstallDirs is included near the top before add_subdirectory().

# Create configuration file template
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/sdfx.pc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/sdfx.pc"
    @ONLY
)

# Install pkg-config file
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/sdfx.pc"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig"
)

# Print configuration information
message(STATUS "SDFX Configuration:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "  Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "  openHiTLS root: ${OpenHiTLS_ROOT_DIR}")
message(STATUS "  openHiTLS version: ${OpenHiTLS_VERSION}")
message(STATUS "  Transport type: ${SDFX_TRANSPORT_TYPE}")
message(STATUS "  Build daemon: ${BUILD_DAEMON}")
message(STATUS "  Build SDK: ${BUILD_SDK}")
message(STATUS "  Build CLI: ${BUILD_CLI}")
message(STATUS "  Build tests: ${BUILD_TESTS}")
message(STATUS "  Build examples: ${BUILD_EXAMPLES}")

# Show found libraries
if(NOT WIN32)
message(STATUS "Found openHiTLS libraries:")
if(OpenHiTLS_CRYPTO_LIBRARY)
    message(STATUS "  libhitls_crypto: ${OpenHiTLS_CRYPTO_LIBRARY}")
endif()
if(OpenHiTLS_BSL_LIBRARY)
    message(STATUS "  libhitls_bsl: ${OpenHiTLS_BSL_LIBRARY}")
endif()
if(OpenHiTLS_TLS_LIBRARY)
    message(STATUS "  libhitls_tls: ${OpenHiTLS_TLS_LIBRARY}")
endif()
if(OpenHiTLS_PKI_LIBRARY)
    message(STATUS "  libhitls_pki: ${OpenHiTLS_PKI_LIBRARY}")
endif()
if(OpenHiTLS_AUTH_LIBRARY)
    message(STATUS "  libhitls_auth: ${OpenHiTLS_AUTH_LIBRARY}")
endif()
if(OpenHiTLS_BOUNDSCHECK_LIBRARY)
    message(STATUS "  libboundscheck: ${OpenHiTLS_BOUNDSCHECK_LIBRARY}")
else()
    message(STATUS "  libboundscheck: not found (optional)")
endif()
endif()
