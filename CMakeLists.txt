CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

project(csgo-psl64)

# Source files
file(GLOB HEADERS src/*.h)
file(GLOB SOURCES src/*.c)
add_library(csgo-psl64 ${HEADERS} ${SOURCES})  

# Generate examples process
add_executable(scanner src/main.c)
target_link_libraries(scanner csgo-psl64)