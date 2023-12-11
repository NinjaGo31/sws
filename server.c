#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/wait.h>

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <libgen.h>

#include "server.h"
#include "sws.h"
#include "util.h"

#define BUFFER_SIZE 32768
#define PARSE_SIZE 4
#define TIMEOUT 600
#define SERVER "Server: sws 1.0\n"
#define CONTENT_TYPE "Content-Type: text/html\n"
#define HTTP "HTTP/1.0 "

enum client_request {REQUEST_TYPE, URI, HTTP_TYPE};
enum cli_or_serv {SERVER_IP, CLIENT_IP};

int mod_since = 0, clientfd = -1;
struct sockaddr_in6 client;
socklen_t cliaddrlen;

char *get_ip(int req_cli_ip, char *ip, int ip_size) {
    struct sockaddr_storage addr;
    struct sockaddr_in *s4;
    struct sockaddr_in6 *s6;
    socklen_t length;

    if (req_cli_ip) { /* Request Client IP */
        if (getpeername(clientfd, (struct sockaddr *)&addr, &length) < 0) {
            return NULL;
        }
    } else { /* Request Server IP */
        if (getpeername(server_socket, (struct sockaddr *)&addr, &length) < 0) {
            return NULL;
        }
    }
    if (domain == AF_INET) {
        s4 = (struct sockaddr_in *)&addr;
        inet_ntop(AF_INET, &s4->sin_addr, ip, ip_size);
    } else {
        s6 = (struct sockaddr_in6 *)&addr;
        inet_ntop(AF_INET6, &s6->sin6_addr, ip, ip_size);
    }

    return ip;
}

int file_list(char *basepath, char *list[], size_t size) {
    struct dirent **dirp;
    int num_files, i;
    size_t j = 0;

    if ((num_files = scandir(basepath, &dirp, NULL, alphasort)) < 0) {
        return 1;
    }

    for (i = 0; i < num_files && j < size; i++) {
        if (strncmp(dirp[i]->d_name, ".", 1) == 0) continue;
        else {
            list[j] = malloc(strlen(dirp[i]->d_name) + 1);
            strncpy(list[j], dirp[i]->d_name, strlen(dirp[i]->d_name));
            j++;
        }
    }

    for (i = 0; i < num_files; i++) {
        (void)free(dirp[i]);
    }
    (void)free(dirp);
    return 0;
}

char** cgi_environment(char **environment, char *request[], char *query_str){
    int i = 0;
    char port_buf[BUFSIZ];
    char req_buf[BUFSIZ];
    char serv_name[BUFSIZ];
    char script_name[BUFSIZ];
    char query[BUFSIZ];
    char remote[BUFSIZ];
    char ip[INET6_ADDRSTRLEN];

    if(getsockname(server_socket,(struct sockaddr*) server, &serv_size) == -1){
        fprintf(stderr, "sws: getsockname error: %s\n", strerror(errno));
    }
    
    environment[i++] = "AUTH_TYPE=Basic";
    environment[i++] = "GATEWAY_INTERFACE=CGI/1.1";
    environment[i++] = "PATH_INFO="; /*need to implement*/
    sprintf(query, "QUERY_STRING=%s\n", query_str);
    environment[i++] = query;
    sprintf(remote, "REMOTE_ADDR=%s\n", get_ip(CLIENT_IP, ip, INET6_ADDRSTRLEN));
    environment[i++] = remote;
    sprintf(req_buf, "REQUEST_METHOD=%s\n", request[REQUEST_TYPE]);
    environment[i++] = req_buf;
    sprintf(script_name, "SCRIPT_NAME=%s\n", request[URI]);
    environment[i++] = script_name;
    sprintf(serv_name, "SERVER_NAME=%s\n", get_ip(SERVER_IP, ip, INET6_ADDRSTRLEN));
    environment[i++] = serv_name;
    sprintf(port_buf, "SERVER_PORT=%d\n", port);
    environment[i++] = port_buf;
    environment[i++] = "SERVER_PROTOCOL=HTTP/1.0";
    environment[i++] = "SERVER_SOFTWARE=Apache/2.4.54 (Unix) OpenSSL/1.1.1k";

    return environment;

}

void exec_cgi(char* request[], char *query_str) {
    int fdout[2], fderr[2];
    int n;
    char *outbuf[BUFSIZ];
    char *errbuf[BUFSIZ]; 
    int errlen = BUFSIZ -1;
    int outlen = BUFSIZ -1;
    char executable[BUFSIZ];
    char *environment[11];
    char *command_args[2];
    char *filename;
    pid_t pid;

    filename = basename(request[URI]);
    executable[0] = '\0';
    strcat(executable, "./");
    strcat(executable, filename);

    command_args[0] = filename;
    command_args[1] = '\0';

    if (pipe(fdout) < 0) {
        (void)fprintf(stderr, "sws: pipe : %s\n", strerror(errno));
        send_response(500, request, NULL);
    }

    if (pipe(fderr) < 0) {
        (void)fprintf(stderr, "sws: pipe : %s\n", strerror(errno));
        send_response(500, request, NULL);
    }
    /*set environment*/
    cgi_environment(environment, request, query_str);

    /*not sure if signals are needed*/
    if ((pid = fork()) < 0) {
        (void)fprintf(stderr, "sws: fork : %s\n", strerror(errno));
        send_response(500, request, NULL);
        /*return EXIT_FAILURE;*/
    }

    if (pid > 0) {
        /*parent process*/
        /*close write ends*/
        (void)close(fdout[1]);
        (void)close(fderr[1]);

        if ((n = read(fdout[0], outbuf, outlen)) < 0){
            (void)fprintf(stderr, "sws: Unable to read from pipe: %s\n", strerror(errno));
            send_response(500, request, NULL);
            /*return EXIT_FAILURE;*/
        }

        if ((n = read(fderr[0], errbuf, errlen)) < 0) {
            (void)fprintf(stderr, "sws: Unable to read from pipe: %s\n", strerror(errno));
            send_response(500, request, NULL);
            /*return EXIT_FAILURE;*/
        }
        /*close read ends*/
        (void)close(fdout[0]);
        (void)close(fderr[0]);

        if (waitpid(pid, NULL, 0) < 0){
            (void)fprintf(stderr, "sws: waitpid: %s\n", strerror(errno));
            send_response(500, request, NULL);
            return;
            /*return EXIT_FAILURE;*/
        }
    } else {
        /*child process*/
        /*close read ends*/
        (void)close(fdout[0]);
        (void)close(fderr[0]);

        if (dup2(fdout[1], STDOUT_FILENO) < 0){
            (void)fprintf(stderr, "sws: dup2 to stdout: %s\n", strerror(errno));
            send_response(500, request, NULL);
            return;
            /*return EXIT_FAILURE;*/
        }

        if (dup2(fderr[1], STDERR_FILENO) < 0){
            (void)fprintf(stderr, "sws: dup2 to stderr: %s\n", strerror(errno));
            send_response(500, request, NULL);
            return;
           /*return EXIT_FAILURE;*/
        }

        if (chdir(cgi_dir) < 0){
            (void)fprintf(stderr, "sws: could not change to directory: %s\n", 
                            strerror(errno));
            send_response(500, request, NULL);
           /*return EXIT_FAILURE;*/
        }
        execvpe(executable, command_args, environment);
        /*close write ends*/
        (void)close(fdout[1]);
        (void)close(fderr[1]);
    }
}

void logging(char *ip_addr, char *err_time_buf, char *request[], 
                int code, long int file_size) {
    char log_output[BUFSIZ];
    int nr;
    bzero(log_output, sizeof(log_output));

    sprintf(log_output, "%s %s \"%s %s %s\" %d %ld\r\n", ip_addr, err_time_buf,
     request[REQUEST_TYPE], request[URI], request[HTTP_TYPE], code, file_size);

    if(debug){
        fprintf(stdout, "%s", log_output);
    }
    else if(l_flag){
        if ((nr = write(log_fd, log_output, sizeof(log_output))) < 0) {
            fprintf(stderr, "sws: failed to write to log. %s.\n",
                strerror(errno));
        }
    }

}

void send_response(int code, char *request[], const char *path) {
    char* status_str;
    time_t curr_time;
    time_t err_time;
    char general_info[BUFSIZ];
    char time_buf[BUFSIZ];
    char err_time_buf[BUFSIZ];
    char last_mod_buf[BUFSIZ];
    char content_len[BUFSIZ];
    char file[BUFSIZ];
    struct tm gmt;
    struct stat last_mod;
    int error_flag = 0;
    char ip_addr[INET6_ADDRSTRLEN];

    if (path != NULL) {
        bzero(file, sizeof(file));
        strncpy(file, path, strlen(path));
    }

    bzero(general_info, sizeof(general_info));
    bzero(time_buf, sizeof(general_info));
    bzero(err_time_buf, sizeof(general_info));
    bzero(last_mod_buf, sizeof(general_info));
    bzero(content_len, sizeof(general_info));

    switch(code) {
        case 200:
            status_str = "OK";
            break;
        case 201:
            status_str = "Created";
            break;
        case 202:
            status_str = "Accepted";
            break;
        case 204:
            status_str = "No Content";
            break;
        case 304:
            status_str = "Not Modified";
            break;
        case 400:
            status_str = "Bad Request";
            error_flag = 1;
            break;
        case 401:
            status_str = "Unauthorized";
            error_flag = 1;
            break;
        case 403:
            status_str = "Forbidden";
            error_flag = 1;
            break;
        case 404:
            status_str = "Not Found";
            error_flag = 1;
            break;
        case 500:
            /* Execution, write, forking fails */
            status_str = "Internal Server Error";
            error_flag = 1;
            break;
        case 501:
            status_str = "Not Implemented";
            error_flag = 1;
            break;
        case 503:
            /* Return if you run out of memory or file descriptors */
            status_str = "Service Unavailable";
            error_flag = 1;
            break;
    }

    sprintf(general_info, "%s %d %s\r\n", HTTP, code, status_str);

    /*send date*/
    time(&curr_time);
    gmt = *gmtime(&curr_time);
    strftime(time_buf, sizeof(time_buf), "Date: %A, %d %B %Y %H:%M:%S GMT\r\n", &gmt);

    /*send last modified*/
    if (error_flag != 1 && file != NULL) {
        stat(file, &last_mod);
        gmt = *gmtime(&last_mod.st_mtime);
        strftime(last_mod_buf, sizeof(last_mod_buf), "Last-Modified: %A, %d %B %Y %H:%M:%S GMT\r\n", &gmt);
    }

    /*send content length*/
    if (error_flag == 1) {
        sprintf(content_len, "Content-Length: 0\r\n");
    } else {
        sprintf(content_len, "Content-Length: %ld\r\n", last_mod.st_size);
    }
    

    if ((l_flag && log_fd > 0) || debug) {
        /*get client IP address*/
        get_ip(CLIENT_IP, ip_addr, INET6_ADDRSTRLEN);
        /*time request was recieved*/
        time(&err_time);
        gmt = *gmtime(&err_time);
        strftime(err_time_buf, sizeof(err_time_buf), "%Y-%B-%dT%H:%M:%SZ", &gmt);
        /* Enter logging function */
        if (error_flag) {
            logging(ip_addr, err_time_buf, request, code, 0);
        } else {
            logging(ip_addr, err_time_buf, request, code, last_mod.st_size);
        }
    }

    send(clientfd, general_info, strlen(general_info), 0);
    send(clientfd, time_buf, strlen(time_buf), 0);
    send(clientfd, SERVER, strlen(SERVER), 0);
    send(clientfd, last_mod_buf, strlen(last_mod_buf), 0);
    send(clientfd, CONTENT_TYPE, strlen(CONTENT_TYPE), 0);
    send(clientfd, content_len, sizeof(content_len), 0);
}

void parse(char buffer[]) {
    char *other_requests[] = {"POST", "PUT", "DELETE", "CONNECT", 
                                "OPTIONS", "TRACE", "PATCH"};
    char *buf[BUFSIZ], *lines[BUFSIZ], *list[BUFSIZ];
    char output[BUFFER_SIZE], index_output[BUFFER_SIZE];
    char user[PATH_MAX], client_dir[PATH_MAX];
    char *client_path, *tmp_path, *query_str, *tmp;
    char *arg, *traverse, *nul;
    char index_temp[BUFSIZ];

    int i, file_fd, n;
    int user_path = 0, invalid = 1;
    size_t arr_len = sizeof(other_requests) / sizeof(other_requests[0]);
    size_t size = strlen(buffer);
    size_t e = 0;
    size_t index;

    struct stat fileInfo;
    struct tm time_req, tm, *file_mtime;
    time_t raw_file_time, raw_time_req;

    file_mtime = &tm;
    memset(&time_req, 0, sizeof(time_req));
    memset(&tm, 0, sizeof(tm));

    /* Parsing */
    traverse = buffer;
    i = 0;
    while((traverse < buffer + size) &&
            ((nul = strstr(traverse, "\r")) != NULL)) {
        if (traverse == nul) break;
        lines[i] = traverse;
        *nul = '\0';
        i++;
        traverse = nul + 1;
    }
    lines[i] = NULL;

    i = 0;
    arg = strtok(lines[0], " ");
    while(arg != NULL) {
        buf[i++] = arg;
        arg = strtok(NULL, " ");
    }
    buf[i] = NULL;
    
    tmp_path = strtok(buf[URI], "?");
    tmp = strtok(NULL, "?");
    if (tmp != NULL) query_str = tmp;

    if (lines[1] != NULL) {
        arg = strtok(lines[1], ":");
        if (strncmp(arg, "If-Modified-Since", 18) != 0) {
            send_response(400, buf, NULL);
            return;
        } else {
            mod_since = 1;
            arg = strtok(NULL, ":");
            if (strptime(arg, "%a, %d %m %Y %H:%M:%S GMT", &time_req) == NULL) {
                send_response(400, buf, NULL);
                return;
            }
            if ((raw_time_req = mktime(&time_req)) < 0) {
                send_response(500, buf, NULL);
                return;
            }
        }
    }

    if (tmp_path[0] != '/') {
        send_response(400, buf, NULL);
        return;
    } else {
        tmp_path++;
    }

    if (tmp_path[0] == '~') {
        user_path = 1;
        tmp_path++;
    }

    if (user_path) {
        bzero(user, sizeof(user));
        strncpy(user, tmp_path, strlen(tmp_path));
        if (user_dir(user, client_dir) != 0) {
            send_response(400, buf, NULL);
            return;
        }
        client_path = client_dir;
    } else {
        if ((client_path = getpath(tmp_path)) == NULL) {
            if (errno == ENOENT) {
                send_response(404, buf, NULL);
                return;
            } else {
                send_response(400, buf, NULL);
                return;
            }
        } else if ((strncmp(dir, client_path, strlen(dir)) != 0) && !user_path) {
            send_response(403, buf, NULL);
            return;
        }
    }

    if ((strncmp(buf[HTTP_TYPE], "HTTP/1.0", 8) != 0)) {
        invalid = 0;
        send_response(501, buf, NULL);
        return;
    }

    if ((strncmp(buf[REQUEST_TYPE], "GET", 3) == 0)) {
        /* Implement GET functionality */
        if (c_flag && (strncmp(tmp_path, "/cgi-bin", 8) == 0)) {
            if (access(client_path, R_OK | X_OK) != 0) {
                send_response(403, buf, NULL);
                return;
            } else {
                send_response(200, buf, NULL);
                exec_cgi(buf, query_str);
                return;
            }
        }
        if (stat(client_path, &fileInfo) < 0){
            send_response(404, buf, NULL);
        }
        if (mod_since) {
            gmtime_r(&fileInfo.st_mtime, file_mtime);
            if ((raw_file_time = mktime(file_mtime)) < 0){
                send_response(500, buf, NULL);
                return;
            }
            if (raw_time_req > raw_file_time) {
                send_response(304, buf, NULL);
            }
        }
        /*client path is a directory*/
        if (S_ISDIR(fileInfo.st_mode)) {
            strcpy(index_temp, client_path);
            strncat(index_temp, "/index.html", 10);
            if ((file_fd = open(index_temp, O_RDONLY)) < 0) {
                /*index.html does not exist*/
                if (file_list(client_path, list, BUFSIZ) == 1) {
                    send_response(500, buf, NULL);
                    return;
                } else {
                    send_response(200, buf, client_path);
                    for (e = 0; e < sizeof(list) && list[e] != NULL; e++) {
                        send(clientfd, list[e], strlen(list[e]), 0);
                        send(clientfd, "\n", 1, 0);
                        (void)free(list[e]);
                    }
                    return;
                }
            } else {
                /*index.html exists*/
                if((n = read(file_fd, index_output, sizeof(index_output))) < 0) {
                    send_response(500, buf, NULL);
                    close(file_fd);
                    return;
                }
                send_response(200, buf, client_path);
                while((n = read(file_fd, index_output, sizeof(index_output))) != -1 && n !=0){
                    send(clientfd, index_output, strlen(index_output), 0);
                }
                close(file_fd);
            }
        /*client path is a file*/
        } else if (S_ISREG(fileInfo.st_mode)){
            if ((file_fd = open(client_path, O_RDONLY)) < 0) {
                if (errno == ENOENT) {
                    send_response(404, buf, NULL);
                } else {
                    send_response(400, buf, NULL);
                }
            } else {
                send_response(200, buf, client_path);
                while((n = read(file_fd, output, sizeof(output))) != -1 && n !=0){
                    send(clientfd, output, strlen(output), 0);
                }
                close(file_fd);
            }
        } else {
            send_response(404, buf, NULL);
        }
    } else if (strncmp(buf[REQUEST_TYPE], "HEAD", 4) == 0) {
        if ((file_fd = open(client_path, O_RDONLY)) < 0) {
            if (errno == ENOENT) {
                send_response(404, buf, NULL);
            } else {
                send_response(400, buf, NULL);
            }
        } else {
            send_response(200, buf, client_path);
            (void)close(file_fd);
        }
    } else {
        for (index = 0; index < arr_len; index++) {
            if (strncmp(buf[REQUEST_TYPE], other_requests[index],
                strlen(other_requests[index])) == 0) {
                invalid = 0;
                send_response(501, buf, NULL);
            }
        }
        if (invalid) {
            send_response(400, buf, NULL);
        }
        /* Child process exits successfully */
    }
}

void handle_connection() {
    int read_val;
    do {
        char buf[BUFSIZ];
        bzero(buf, sizeof(buf));
        if ((read_val = read(clientfd, buf, BUFSIZ)) < 0) {
           send_response(500, NULL, NULL);
           return;
        } else {
            parse(buf);
        }
    } while(read_val != 0);
    (void)close(clientfd);
}

int server_socket_handle() {
    pid_t pid;

    cliaddrlen = sizeof(client);
    if ((clientfd = accept(server_socket, (struct sockaddr *)&client,
                    &cliaddrlen)) < 0 && errno != EINTR) {
        fprintf(stderr, "sws: failed to accepted incoming connection. %s.\n",
                strerror(errno));
        return EXIT_FAILURE;
    }

    /* Create child process that handles server socket */
    if ((pid = fork()) < 0) {
        fprintf(stderr, "sws: unable to fork process %s\n", strerror(errno));
        return EXIT_FAILURE;
    } else if(pid == 0) {
        if (alarm(TIMEOUT) == (unsigned int) -1) {
            fprintf(stderr, "sws: alarm unable to set timeout %s\n", strerror(errno));
        }
        handle_connection();
    }
    /*Wait for client to send a message for a given amount of time (set an alarm before the read)*/
    (void)alarm(0);
    /*If alarm goes off and no read was made, just terminate the connection.*/
    return EXIT_SUCCESS;
}
