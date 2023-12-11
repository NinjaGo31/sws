#ifndef UTIL_H_
#define UTIL_H_

void reap();
void check_dir(char *path);
char *getpath(char *dir);
int user_dir(char path[], char dir[]);
int is_int(const char* prt);
int parse_port(const char* input, int* prt);

#endif