#ifndef SERVER_H_
#define SERVER_H_

int server_socket_handle();
void handle_connection(int socket_fd);
void parse(char* buffer, int clientfd);
void send_response(int clientfd, int code, char *request[]);
void logging(int ip_addr, char *err_time_buf, char *request[], int code, char *content_len);
void exec_cgi(int clientfd, char* request[], char *query_str);
char** cgi_environment(char **environment, char *request[], char *query_str);
int file_list(char *basepath, char *list[], size_t size);

#endif