#include <sys/socket.h>

#define ERROR           -1
#define CONNECTIONS     5

extern int client_sockets[CONNECTIONS];
extern int server_socket, num;
extern socklen_t addrlen, serv_size;
extern void *server;