cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(nrf54l15_sniffer)

# shared/ is a peer of both firmwares, belonging to neither: nothing about
# the wire format is specific to a board, and while it lived inside the
# C6's tree this build reached into the other board's directory to get it.
#
# frame.c is COMPILED here, not copied: two implementations of one wire
# format drift, and the drift would be invisible -- a capture from one
# board would decode and a capture from the other would not, with nothing
# to say which was wrong.
#
# Byte-identity between the boards is therefore a property of the build rather
# than something the tests have to catch. The golden vectors go back to
# guarding what they were written for, which is drift between C and Python.
target_sources(app PRIVATE
    src/main.c
    src/link.c
    src/radio154.c
    src/control.c
    src/log_backend_sn.c
    ../shared/frame.c
)
target_include_directories(app PRIVATE ../shared)

# Mirrors firmware/main/CMakeLists.txt, so both boards are driven the same way.
#   west build -b xiao_nrf54l15/nrf54l15/cpuapp -- -DSN_MODE=0
# SN_MODE 0 = conformance burst (default, used by the host test suite)
# SN_MODE 2 = capture
if(DEFINED SN_MODE)
    target_compile_definitions(app PRIVATE SN_MODE=${SN_MODE})
endif()
