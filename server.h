#ifndef SERVER_H_
#define SERVER_H_

int server_socket_handle();
void handle_connection(int socket_fd);
void parse(char* buffer, int clientfd);
void send_response(int clientfd, int code, const char *request);

#endif