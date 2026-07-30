set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)
set(CMAKE_C_COMPILER /ucrt64/bin/x86_64-w64-mingw32-gcc.exe)
set(CMAKE_RC_COMPILER /ucrt64/bin/windres.exe)

# MSYS CMake otherwise writes /d/... include paths into response files.
# Native MinGW programs do not apply MSYS argument conversion to file contents.
set(CMAKE_C_USE_RESPONSE_FILE_FOR_INCLUDES OFF CACHE BOOL "" FORCE)
set(CMAKE_C_USE_RESPONSE_FILE_FOR_OBJECTS OFF CACHE BOOL "" FORCE)
