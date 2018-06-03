#ifndef UTILS_H
#define UTILS_H

#include <fcntl.h>

long findPidByName(char *procname);

void findHeapAddress(long pid, unsigned long *heapStart,
                     unsigned long *heapEnd);

int readMemory(long pid, unsigned long addr, void *buffer, size_t size);

int writeMemory(long pid, unsigned long addr, void *buffer, size_t size);

int memoryPatternScan(long pid, unsigned long startAddr, unsigned long endAddr,
                      char *pattern, size_t size, size_t offset,
                      unsigned long *addr);

#endif