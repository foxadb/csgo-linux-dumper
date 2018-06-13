#define _GNU_SOURCE
#include "utils.h"
#include <dirent.h>
#include <fcntl.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

long findPidByName(char* processName) {
  // Pid to be returned
  long pid = -1;

  // Regex for pid and process name
  regex_t number;
  regex_t name;
  regcomp(&number, "^[0-9]\\+$", 0);
  regcomp(&name, processName, 0);

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

void findMapRegionAddress(long pid, char* name, unsigned long* start,
                          unsigned long* end) {
  // Open maps file
  char mapsfile[64];
  sprintf(mapsfile, "/proc/%ld/maps", pid);
  FILE* fp = fopen(mapsfile, "r");
  if (fp == NULL) {
    *start = -1;
  } else {
    // Read the maps file
    char* line = NULL;
    size_t len = 0;
    int found = 0;
    while (getline(&line, &len, fp) != -1) {
      if (strstr(line, name) != NULL) {
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

        // Parse start and end address
        if (!found) {
          *start = (unsigned long)strtol(addr1, NULL, 16);
        }
        *end = (unsigned long)strtol(addr2, NULL, 16);

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

void memoryPatternScan(long pid, unsigned long startAddr, unsigned long endAddr,
                       char* pattern, size_t size, size_t offset,
                       unsigned long* addr) {
  char* buf = malloc(size * sizeof(char));  // local buffer
  struct iovec local[1];
  struct iovec remote[1];

  local[0].iov_base = buf;
  local[0].iov_len = size;
  remote[0].iov_base = (void*)startAddr;
  remote[0].iov_len = size;

  unsigned long scanZone = endAddr - startAddr - size;
  while (scanZone > 0) {
    // Read bytes from memory
    process_vm_readv(pid, local, 1, remote, 1, 0);

    // Comparing bytes loop
    size_t counter = 0;
    for (size_t i = 0; i < size; ++i) {
      char remoteByte = buf[i];

      // Parsing a pattern byte from string
      char byteStr[2];
      byteStr[0] = pattern[2 * i];
      byteStr[1] = pattern[2 * i + 1];

      // Unknown byte
      if (byteStr[0] == '?' && byteStr[1] == '?') {
        ++counter;
      } else {
        char patternByte = (char)strtol(byteStr, NULL, 16);
        if (remoteByte == patternByte) {
          counter += 1;
        } else {
          break;
        }
      }
    }

    // Check if all bytes match
    if (counter == size) {
      *addr = (unsigned long)remote[0].iov_base + offset;
      break;
    }

    // Skip to next address
    ++remote[0].iov_base;
    --scanZone;
  }

  free(buf);  // free local buffer
}