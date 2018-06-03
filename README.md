# CS:GO pattern scanner for Linux x64

This tool aimed to get offsets of Counter Strike: Global Offensive on 64 bits Linux.

*Tested on Arch Linux x86_64.*

:warning: I am not liable for VAC bans for using this tool.

## Build

This project requires CMake >= 2.8 for compiling.
```
mkdir build
cd build
cmake ..
make
```

## Run

Run the `scanner` executable with *root permissions*:
```
sudo ./scanner
```
**sudo** is mandatory to have read/write access to `/proc/<pid>/mem` file.

The executable will find the pid alone by looking through the `/proc` directory, then finding the address of the string to hack.