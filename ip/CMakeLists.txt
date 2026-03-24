cmake_minimum_required(VERSION 3.13)

# Initialize pico-sdk
include($ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake)

# Create the library
add_library(ip
        ip.cpp
)

# Add include directories
target_include_directories(ip PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# Link against pico standard library
target_link_libraries(ip
        pico_stdlib
)

# Enable USB output, disable UART output
pico_enable_stdio_usb(ip 1)
pico_enable_stdio_uart(ip 0)