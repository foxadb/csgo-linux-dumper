#ifndef ENTITY_H
#define ENTITY_H

#define TEAM_SPEC 1
#define TEAM_T 2
#define TEAM_CT 3

#define LIFE_ALIVE 0
#define LIFE_DYING 1
#define LIFE_DEAD 2

typedef struct Entity {
  int team;
  int lifeState;
  int health;
} Entity;

void printEntity(Entity *entity);

void readEntity(long pid, long unsigned addr, Entity *entity);

void readPlayerNames(long pid, long unsigned addr, char *names);

#endif