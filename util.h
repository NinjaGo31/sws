#ifndef UTIL_H_
#define UTIL_H_

void check_dir(char *path);
int is_int(const char* port);
int parse_port(const char* input, int* port);
void reap();

#endif