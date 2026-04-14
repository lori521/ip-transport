cmake_minimum_required(VERSION 3.13)

# Initialize pico-sdk
include($ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake)

# Create the library
add_library(manchester_nonblock
    manchester_rx.cpp
    manchester_tx.cpp
    manchester.cpp
    ring_buffer.cpp
)

# Add include directories
target_include_directories(manchester_nonblock PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Link against pico standard library
target_link_libraries(manchester_nonblock
    pico_stdlib
)

# Enable USB output, disable UART output
pico_enable_stdio_usb(manchester_nonblock 1)
pico_enable_stdio_uart(manchester_nonblock 0)