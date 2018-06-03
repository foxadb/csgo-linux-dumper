#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

long findPidByName(char* procname) {
  // Pid to be returned
  long pid = -1;

  // Regex for pid and process name
  regex_t number;
  regex_t name;
  regcomp(&number, "^[0-9]\\+$", 0);
  regcomp(&name, procname, 0);

  // Go to proc dir and open it
  chdir("/proc");
  DIR* proc = opendir("/proc");

  // Iterate through proc dir
  struct dirent* dp;
  char buf[4096];
  while (dp = readdir(proc)) {
    // Only consider dir with pid name
    if (regexec(&number, dp->d_name, 0, 0, 0) == 0) {
      chdir(dp->d_name);

      // Open cmdline file
      int fd = open("cmdline", O_RDONLY);

      // Read file into the buffer
      buf[read(fd, buf, (sizeof buf) - 1)] = '\0';

      if (regexec(&name, buf, 0, 0, 0) == 0) {
        if (pid != -1) {
          fprintf(stderr, "Second process %s found: %s\n", dp->d_name, buf);
          return -1;
        }
        pid = atoi(dp->d_name);
        printf("Process %d found: %s\n", pid, buf);
      }

      // Close cmdline file
      close(fd);

      // Go back to proc dir
      chdir("..");
    }
  }

  // Close proc dir
  closedir(proc);

  return pid;
}

void findHeapAddress(long pid, unsigned long* heapStart,
                     unsigned long* heapEnd) {
  // Open maps file
  char mapsfile[64];
  sprintf(mapsfile, "/proc/%ld/maps", pid);
  FILE* fp = fopen(mapsfile, "r");
  if (fp == NULL) {
    *heapStart = -1;
  } else {
    // Read the maps file
    char* line = NULL;
    size_t len = 0;
    char* heapWord = "[heap]";
    int found = 0;
    while (getline(&line, &len, fp) != -1 && !found) {
      if (strstr(line, heapWord) != NULL) {
        char addr1[16];
        char addr2[16];
        int i = 0;

        while (line[i] != '-') {
          addr1[i] = line[i];
          ++i;
        }
        addr1[i] = '\0';

        // Skip separator
        ++i;
        int off = i;

        while (line[i] != '-') {
          addr2[i - off] = line[i];
          ++i;
        }
        addr2[i - off] = '\0';

        // Parse heap start and end address
        *heapStart = (unsigned long)strtol(addr1, NULL, 16);
        *heapEnd = (unsigned long)strtol(addr2, NULL, 16);

        // Found
        found = 1;
      }
    }

    // Free line
    if (line) {
      free(line);
    }

    // Close file
    fclose(fp);
  }
}

int readMemory(long pid, unsigned long addr, void* buffer, size_t size) {
  struct iovec local[1];
  struct iovec remote[1];

  local[0].iov_base = buffer;
  local[0].iov_len = size;
  remote[0].iov_base = (void*)addr;
  remote[0].iov_len = size;

  return (process_vm_readv(pid, local, 1, remote, 1, 0) == size);
}

int writeMemory(long pid, unsigned long addr, void* buffer, size_t size) {
  struct iovec local[1];
  struct iovec remote[1];

  local[0].iov_base = buffer;
  local[0].iov_len = size;
  remote[0].iov_base = (void*)addr;
  remote[0].iov_len = size;

  return (process_vm_writev(pid, local, 1, remote, 1, 0) == size);
}

int memoryPatternScan(long pid, unsigned long startAddr, unsigned long endAddr,
                      char* pattern, size_t size, size_t offset,
                      unsigned long* addr) {
  struct iovec local[1];
  struct iovec remote[1];
  char* buf = malloc(size * sizeof(char));  // local buffer

  local[0].iov_base = buf;
  local[0].iov_len = size;
  remote[0].iov_base = (void*)startAddr;
  remote[0].iov_len = size;

  unsigned long scanZone = endAddr - startAddr - size;
  while (scanZone > 0) {
    process_vm_readv(pid, local, 1, remote, 1, 0);

    // Comparing bytes
    size_t counter = 0;
    for (size_t i = 0; i < size; ++i) {
      char remoteByte = buf[i];

      char byteStr[2];
      byteStr[0] = pattern[2 * i];
      byteStr[1] = pattern[2 * i + 1];

      // Unknown byte
      if (byteStr[0] == '?' && byteStr[1] == '?') {
        ++counter;
      } else {
        char patternByte = (char)strtol(byteStr, NULL, 16);
        counter += (remoteByte == patternByte);
      }
    }

    // Check if bytes match
    if (counter == size) {
      free(buf);
      *addr = (unsigned long)remote[0].iov_base + offset;
      return 0;
    }
    ++remote[0].iov_base;
    --scanZone;
  }

  free(buf);
  return -1;
}