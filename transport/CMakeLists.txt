# Initialize pico-sdk
include($ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake)

# Create the library
add_library(tcp
        tcp.cpp
)

# Add include directories
target_include_directories(tcp PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Link against pico standard library
target_link_libraries(tcp
    pico_stdlib
)

# Enable USB output, disable UART output
pico_enable_stdio_usb(tcp 1)
pico_enable_stdio_uart(tcp 0)