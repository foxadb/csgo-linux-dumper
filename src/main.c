#include <stdio.h>
#include <stdlib.h>
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

  printf("Scanning memory...\n");

  unsigned long localPlayerLea = 0;
  memoryPatternScan(pid, clientStart, clientEnd, PAT_LOCALPLAYER_LEA,
                    PAT_LOCALPLAYER_LEA_SIZE, PAT_LOCALPLAYER_LEA_OFF, &localPlayerLea);

  unsigned long code = 0;
  readMemory(pid, localPlayerLea, &code, sizeof(unsigned int));
  unsigned long m_addressOfLocalPlayer =
      localPlayerLea + code + 0x4;

  unsigned long localPlayer;
  readMemory(pid, m_addressOfLocalPlayer, &localPlayer, sizeof(long));
  printf("LocalPlayer: 0x%lx\n", localPlayer);

  int team, health;
  unsigned long teamAddr = localPlayer + OFF_MY_TEAM;
  unsigned long healthAddr = localPlayer + OFF_MY_HEALTH;
  readMemory(pid, teamAddr, &team, sizeof(int));
  readMemory(pid, healthAddr, &health, sizeof(int));
  
  printf("Team: %d (0x%lx)\n", team, teamAddr);
  printf("Health: %d (0x%lx)\n", health, healthAddr);

  return EXIT_SUCCESS;
}