#ifndef UTIL_H_
#define UTIL_H_

void reap();
void check_dir(char *path);
char *getpath(char *dir);
int is_int(const char* port);
int parse_port(const char* input, int* port);

#endif