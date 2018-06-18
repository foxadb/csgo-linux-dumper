# CS:GO offsets dumper for Linux x64

This tool aims to get offsets of Counter Strike: Global Offensive on 64 bits Linux.
It uses pattern scanning to find offsets.

*Tested on Arch Linux x86_64.*

:warning: I am not liable for VAC bans for using this program.

## Offsets

- LocalPlayer
- PlayerResources
- Glow

## Build

This project requires CMake >= 2.8 for compiling.
```
mkdir build
cd build
cmake ..
make
```

## Run

Run the `dumper` executable with *root permissions*:
```
sudo ./dumper
```
**sudo** is mandatory to have read/write access to `/proc/<pid>/mem` file.

The executable will find the pid alone by looking through the `/proc` directory, then finding the address of the string to hack.