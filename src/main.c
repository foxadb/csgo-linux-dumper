#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "entity.h"
#include "patterns.h"
#include "utils.h"

int main(int argc, char* argv[]) {
  printf("CS:GO offsets dumper for Linux x64 (by foxadb)\n");

  //////////////////////////// PARSING MEMORY MAP //////////////////////////////

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

  ///////////////////////////// SCANNING MEMORY ////////////////////////////////

  printf("Scanning memory...\n\n");
  time_t startTime = clock();

  // Read LocalPlayer LEA address
  unsigned long localPlayerLea = 0;
  memoryPatternScan(pid, clientStart, clientEnd, PAT_LOCALPLAYER_LEA,
                    PAT_LOCALPLAYER_LEA_SIZE, PAT_LOCALPLAYER_LEA_OFF,
                    &localPlayerLea);

  // Find LocalPlayer pointer address
  unsigned long localPlayerPtr = 0;
  readMemory(pid, localPlayerLea, &localPlayerPtr, sizeof(unsigned int));
  localPlayerPtr += localPlayerLea + 0x4;
  printf("LocalPlayer = 0x%lx\n", localPlayerPtr - clientStart);

  // Read LocalPlayer memory
  unsigned long localPlayer = 0;
  Entity* entity = malloc(sizeof(Entity));
  readMemory(pid, localPlayerPtr, &localPlayer, sizeof(unsigned long));
  readEntity(pid, localPlayer, entity);
  printEntity(entity);
  printf("\n");

  // Find PlayerResources pointer address
  unsigned long foundPlayerResources = 0;
  memoryPatternScan(pid, clientStart, clientEnd, PAT_PLAYER_RESOURCES_PTR,
                    PAT_PLAYER_RESOURCES_PTR_SIZE, PAT_PLAYER_RESOURCES_PTR_OFF,
                    &foundPlayerResources);
  unsigned long playerResourcesPtr = 0;
  readMemory(pid, foundPlayerResources, &playerResourcesPtr,
             sizeof(unsigned int));
  playerResourcesPtr += foundPlayerResources + 0x4;
  printf("PlayerResources = 0x%lx\n", playerResourcesPtr - clientStart);

  // Read player names
  char* names = malloc(4096 * sizeof(char)); // 64 names = 64 * 64 char
  readPlayerNames(pid, playerResourcesPtr, names);
  for (int i = 0; i <= 10; ++i) {
    printf("Name %d: %s\n", i, names + 64 * i);
  }

  // Timer measure
  time_t endTime = clock();
  printf("Time elapsed: %.2f s\n",
         (float)(endTime - startTime) / CLOCKS_PER_SEC);

  // Free memory
  free(entity);
  free(names);

  return EXIT_SUCCESS;
}