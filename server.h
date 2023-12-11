#ifndef SERVER_H_
#define SERVER_H_

int server_socket_handle();
void handle_connection();
void parse(char buffer[]);
void send_response(int code, char *request[], const char *path);
void logging(char *ip_addr, char *err_time_buf, char *request[], int code, long int file_size);
void exec_cgi(char* request[], char *query_str);
char** cgi_environment(char **environment, char *request[], char *query_str);
int file_list(char *basepath, char *list[], size_t size);
char *get_ip(int req_cli_ip, char *ip, int ip_size);
#endif