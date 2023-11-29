#ifndef SWS_H_
#define SWS_H_

#include <sys/socket.h>

#define ERROR           -1
#define CONNECTIONS     5

int client_sockets[CONNECTIONS];
int server_socket;
int num;
int l_flag;
int log_fd;
socklen_t addrlen, serv_size;
void *server;

#endif