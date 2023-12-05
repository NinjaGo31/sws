#ifndef SWS_H_
#define SWS_H_

#include <sys/socket.h>

#define ERROR           -1
#define CONNECTIONS     5

char *cgi_dir = NULL;
char *dir = NULL;
char *log_file = NULL;

int client_sockets[CONNECTIONS];
int server_socket;
int num;
int c_flag, l_flag;
int debug;
int log_fd;

socklen_t addrlen, serv_size;
void *server;

#endif