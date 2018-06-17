#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "offsets.h"
#include "patterns.h"
#include "utils.h"

int main(int argc, char* argv[]) {
  printf("CS:GO offsets dumper for Linux x64 (by foxadb)\n");

  // Process id
  long pid = findPidByName("csgo_linux64");

  if (pid == -1) {
    fprintf(stderr, "Process not found: Please run csgo_linux64\n");
    return EXIT_FAILURE;
  }

  // Find client address
  unsigned long clientStart = -1, clientEnd;
  findMapRegionAddress(pid, "client_client.so", &clientStart, &clientEnd);
  if (clientStart == -1) {
    fprintf(stderr, "client_client.so address not found\n");
    return EXIT_FAILURE;
  }
  printf("client_client.so: 0x%lx - 0x%lx\n", clientStart, clientEnd);

  printf("Scanning memory...\n\n");
  time_t startTime = clock();

  unsigned long localPlayerLea = 0;
  memoryPatternScan(pid, clientStart, clientEnd, PAT_LOCALPLAYER_LEA,
                    PAT_LOCALPLAYER_LEA_SIZE, PAT_LOCALPLAYER_LEA_OFF,
                    &localPlayerLea);

  unsigned long localPlayerPtr = 0;
  readMemory(pid, localPlayerLea, &localPlayerPtr, sizeof(unsigned int));
  localPlayerPtr += localPlayerLea + 0x4;

  unsigned long localPlayer = 0;
  readMemory(pid, localPlayerPtr, &localPlayer, sizeof(long));
  printf("LocalPlayer = 0x%lx\n", localPlayer);

  int team, health, lifeState;
  readMemory(pid, localPlayer + OFF_TEAM, &team, sizeof(int));
  readMemory(pid, localPlayer + OFF_HEALTH, &health, sizeof(int));
  readMemory(pid, localPlayer + OFF_LIFESTATE, &lifeState, sizeof(int));
  printf("Check: Team (%d) Health (%d) Life state (%d)\n\n", team, health, lifeState);

  time_t endTime = clock();
  printf("Time elapsed: %.2f s\n",
         (float)(endTime - startTime) / CLOCKS_PER_SEC);

  return EXIT_SUCCESS;
}