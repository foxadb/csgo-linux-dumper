#include "entity.h"
#include <stdio.h>
#include "offsets.h"
#include "utils.h"

void printEntity(Entity* entity) {
  char* team;
  switch (entity->team) {
    case TEAM_SPEC:
      team = "SPEC";
      break;
    case TEAM_T:
      team = "T";
      break;
    case TEAM_CT:
      team = "CT";
      break;
    default:
      team = "?";
  }

  char* lifeState;
  switch (entity->lifeState) {
    case LIFE_ALIVE:
      lifeState = "ALIVE";
      break;
    case LIFE_DYING:
      lifeState = "DYING";
      break;
    case LIFE_DEAD:
      lifeState = "DEAD";
      break;
    default:
      lifeState = "?";
  }

  printf("Entity { ");
  printf("team: %s, ", team);
  printf("state: %s, ", lifeState);
  printf("health: %d", entity->health);
  printf(" }\n");
}

void readEntity(long pid, long unsigned addr, Entity* entity) {
  readMemory(pid, addr + OFF_TEAM, &entity->team, sizeof(int));
  readMemory(pid, addr + OFF_LIFESTATE, &entity->lifeState, sizeof(int));
  readMemory(pid, addr + OFF_HEALTH, &entity->health, sizeof(int));
}

void readPlayerNames(long pid, long unsigned addr, char* names) {
  // Read PlayerResources memory
  unsigned long playerResources = 0;
  readMemory(pid, addr, &playerResources, sizeof(unsigned long));
  playerResources += OFF_NAMES;

  // Read names
  unsigned long* namePtrs = malloc(64 * sizeof(unsigned long));
  readMemory(pid, playerResources, namePtrs, 64 * sizeof(unsigned long));
  for (int i = 0; i <= 10; ++i) {
    readMemory(pid, namePtrs[i], names + 64 * i, 64 * sizeof(char));
  }
}