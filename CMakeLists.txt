CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

project(csgo-linux-dumper C)

# Source files
file(GLOB HEADERS src/*.h)
file(GLOB SOURCES src/*.c)
add_library(csgo-linux-dumper ${HEADERS} ${SOURCES})  

# Generate examples process
add_executable(dumper src/main.c)
target_link_libraries(dumper csgo-linux-dumper)