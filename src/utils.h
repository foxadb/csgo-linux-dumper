#ifndef UTILS_H
#define UTILS_H

#include <fcntl.h>

/**
 * Find pid by process name
 */
long findPidByName(char *processName);

/**
 * Find start and end heap addresses
 */
void findHeapAddress(long pid, unsigned long *heapStart,
                     unsigned long *heapEnd);

/**
 * Read memory bytes at specific address
 */
int readMemory(long pid, unsigned long addr, void *buffer, size_t size);

/**
 * Write memory bytes at specific address
 */
int writeMemory(long pid, unsigned long addr, void *buffer, size_t size);

/**
 * Scan memory at specific region using a pattern
 *
 * Pattern example: 43b1c8??15??d86974
 * ?? means unknown byte
 */
int memoryPatternScan(long pid, unsigned long startAddr, unsigned long endAddr,
                      char *pattern, size_t size, size_t offset,
                      unsigned long *addr);

#endif