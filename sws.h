#ifndef SWS_H_
#define SWS_H_

#include <sys/socket.h>

#define ERROR           -1
#define CONNECTIONS     5

char *cgi_dir;
char *dir;
char *log_file;

int client_sockets[CONNECTIONS];
int domain;
int server_socket;
int num, port;
int c_flag, l_flag;
int debug;
int log_fd;

socklen_t addrlen, serv_size;
void *server;

#endif