# Transport layer module

# Include subdirectories
add_subdirectory(src)

# Install transport interface header files
install(FILES include/transport_interface.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/sdfx
)