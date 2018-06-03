#include <stdio.h>
#include <stdlib.h>
#include "patterns.h"
#include "utils.h"

int main(int argc, char* argv[]) {
  // Process id
  long pid = findPidByName("csgo_linux64");

  if (pid == -1) {
    fprintf(stderr, "Process id not found\n");
    return EXIT_FAILURE;
  }

  // Find heap start address
  unsigned long heapStart = -1, heapEnd;
  findHeapAddress(pid, &heapStart, &heapEnd);
  if (heapStart == -1) {
    fprintf(stderr, "Heap address not found\n");
    return EXIT_FAILURE;
  }
  printf("Heap: 0x%lx - 0x%lx\n", heapStart, heapEnd);

  printf("Scanning memory...\n");
  unsigned long healthAddr, armorAddr;
  memoryPatternScan(pid, heapStart, heapEnd, P_HEATH, P_HEATH_SIZE, P_HEATH_OFF,
                    &healthAddr);
  armorAddr = healthAddr + 4;

  int health, armor;

  readMemory(pid, healthAddr, &health, sizeof(health));
  printf("(0x%lx) Health: %d\n", healthAddr, health);

  readMemory(pid, armorAddr, &armor, sizeof(armor));
  printf("(0x%lx) Armor: %d\n", armorAddr, armor);

  return EXIT_SUCCESS;
}