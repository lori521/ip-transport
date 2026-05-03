# Initialize pico-sdk
include($ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake)

# Create the library
add_library(tcp
    tcp_packet_io.cpp
    tcp_packet.cpp
    tcp_state_machine.cpp
    tcp_wrapper.cpp
)

# Add include directories
target_include_directories(tcp PUBLIC
    .
    ..
)

target_include_directories(tcp PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/ip
    ${CMAKE_SOURCE_DIR}/ethernet
    ${CMAKE_SOURCE_DIR}/manchester_nonblock
)

# Link against pico standard library
target_link_libraries(tcp
    pico_stdlib
    hardware_pio
    hardware_dma
)

# Enable USB output, disable UART output
pico_enable_stdio_usb(tcp 1)
pico_enable_stdio_uart(tcp 0)