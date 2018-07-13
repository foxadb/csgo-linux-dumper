#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "config.h"
#include "entity.h"
#include "patterns.h"
#include "utils.h"

int main(int argc, char* argv[]) {
  printf("CS:GO offsets dumper for Linux x64 (by foxadb)\n");

  if (getuid() != 0) {
    fprintf(stderr, "Run the program as root (sudo)\n");
    return EXIT_FAILURE;
  }

  //////////////////////////// Parsing memory map //////////////////////////////

  // Process id
  long pid = findPidByName(PROCESS_NAME);

  if (pid == -1) {
    fprintf(stderr, "Process not found: Please run %s\n", PROCESS_NAME);
    return EXIT_FAILURE;
  }

  // Find client address
  unsigned long clientStart = -1, clientEnd;
  findMapRegionAddress(pid, CLIENT_SO, &clientStart, &clientEnd);
  if (clientStart == -1) {
    fprintf(stderr, "Client address not found\n");
    return EXIT_FAILURE;
  }
  printf("Client (%s): 0x%lx - 0x%lx\n", CLIENT_SO, clientStart, clientEnd);

  printf("Scanning memory...\n\n");
  time_t startTime = clock();

  ////////////////////////////// LocalPlayer ///////////////////////////////////

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

  //////////////////////////// PlayerResources /////////////////////////////////

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
  char* names = malloc(4096 * sizeof(char));  // 64 names = 64 * 64 chars
  readPlayerNames(pid, playerResourcesPtr, names);
  for (int i = 0; i <= 10; ++i) {
    printf("Name %d: %s\n", i, names + 64 * i);
  }

  printf("\n");

  ////////////////////////////////// Glow //////////////////////////////////////

  // Find Glow pointer call address
  unsigned long foundGlowPtrCall = 0;
  memoryPatternScan(pid, clientStart, clientEnd, PAT_GLOW_PTR_CALL,
                    PAT_GLOW_PTR_CALL_SIZE, PAT_GLOW_PTR_CALL_OFF,
                    &foundGlowPtrCall);
  unsigned long glowPtrCall = 0;
  readMemory(pid, foundGlowPtrCall, &glowPtrCall, sizeof(unsigned int));
  glowPtrCall += foundGlowPtrCall + 0x4;

  // Find Glow pointer address
  unsigned long glowPtr = 0;
  readMemory(pid, glowPtrCall, &glowPtr, sizeof(unsigned int));
  glowPtr += glowPtrCall + 0x5;
  printf("Glow = 0x%lx\n", glowPtr - clientStart);

  printf("\n");

  ///////////////////////////// End of program /////////////////////////////////

  // Timer measure
  time_t endTime = clock();
  printf("Time elapsed: %.2f s\n",
         (float)(endTime - startTime) / CLOCKS_PER_SEC);

  // Free memory
  free(entity);
  free(names);

  return EXIT_SUCCESS;
}