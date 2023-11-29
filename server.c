#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "server.h"
#include "sws.h"

#define PARSE_SIZE 4
#define TIMEOUT 60
#define SERVER "Server: sws 1.0\n"
#define CONTENT_TYPE "Content-Type: text/html\n"
#define HTTP "HTTP/1.0 "

enum client_request {REQUEST_TYPE, URL, HTTP_TYPE};

void send_response(int clientfd, int code, const char *request) {
    char* status_str;
    char log_info[BUFSIZ];
    time_t curr_time;
    char general_info[BUFSIZ];
    char time_buf[BUFSIZ];
    char last_mod_buf[BUFSIZ];
    char content_len[BUFSIZ];
    struct tm gmt;
    struct stat last_mod;
    int error_flag = 0;

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
        case 304: /* When does this occur? */
            // Occurs if the client brings uses the IF-MODIFIED-SINCE:<timestamp> request
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

    sprintf(general_info, "%s %d %s", HTTP, code, status_str);
    send(clientfd, general_info, strlen(general_info), 0);

    if (error_flag == 1) {
        if (l_flag && log_fd > 0) {
            /* Enter logging function */
        }
    }
    
    /*send date*/
    time(&curr_time);
    gmt = *gmtime(&curr_time);
    strftime(time_buf, sizeof(time_buf), "Date: %A, %d %B %Y %H:%M:%S GMT", &gmt);
    send(clientfd, time_buf, strlen(time_buf),0);

    if (l_flag) {
        // sprintf(log_info, "%s ", ip_addr);
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%SZ", &gmt);
        strncat(log_info, time_buf, strlen(time_buf));
    }

    /*send server*/
    send(clientfd, SERVER, strlen(SERVER), 0);

    /*send last modified*/
    stat(request, &last_mod);
    gmt = *gmtime(&last_mod.st_mtime);
    strftime(last_mod_buf, sizeof(last_mod_buf), "Last-Modified: %A, %d %B %Y %H:%M:%S GMT", &gmt);
    send(clientfd, last_mod_buf, strlen(last_mod_buf), 0);
    
    /*send content type*/
    send(clientfd, CONTENT_TYPE, strlen(CONTENT_TYPE), 0);

    /*send content length*/
    sprintf(content_len, "Content-Length: %ld", last_mod.st_size);
    send(clientfd, content_len, sizeof(content_len), 0);

    if (l_flag) {
        /*strncat(log_info, " \"", 2);
        strncat(log_info, request, strlen(request));
        strncat(log_info, "\"", 2);
        sprintf(log_info, "%s %d %d", log_info, code, last_mod.st_size);*/
    }
}



void parse(char* buffer, int clientfd) {
    char *other_requests[7] = {"POST", "PUT", "DELETE", "CONNECT", 
                                "OPTIONS", "TRACE", "PATCH"};
    /*char* temp;
    char* content;*/
    char* buf[PARSE_SIZE];
    /*char modify_time[BUFSIZ];*/
    int i, file_fd;
    /*int content_len;*/
    /*int total_len = 0;*/
    int invalid = 1;
    
    /* Parsing only for ONE line. Must parse until empty line is read. */
    char* arg = strtok(buffer, " ");
    while(arg != NULL) {
        buf[i++] = arg;
        arg = strtok(NULL, " ");
    }
    buf[i] = NULL;

    if ((strncmp(buf[REQUEST_TYPE], "GET", 3) == 0)) {
        /* Implement GET functionality */
        // What errors are we supposed to catch in the GET/HEAD event? How do we handle them?
        // - The files doesn't exist at all (Send 404)
        // - The file exists, but the client doesn't have access to the file (Send either 401 or 403)
        // - The client's request is OUTSIDE of docroot (Send 403)
        // /home/<user>/sws --> /docroot

        // faccessat(2) might be your best friend in this situation (Would be useful)
        // How can we keep track of where the client is trying to access? Parse by '/' and
        // keep tally of the name of the directory location?
        // ANSWER: Construct an absolute/real path with the docroot path and client path,
        // and then check if the resulting path is under the docroot
        // USE THE realpath(3) function. Must be under the docroot path.
        // Do we hard code the docroot path?
        // No. The last argument is the directory in which you are serving content from. In this case,
        // create an absolute path using this argument.
        if ((file_fd = open(buf[URL], O_RDONLY)) < 0) {
            if (errno == ENOENT) {
                send_response(clientfd, 404, buffer);
            } else {
                send_response(clientfd, 400, buffer);
            }
        }
        /*while ((content_len = read(file_fd, temp, BUFSIZ)) > 0) {
            strncat(content, temp, strlen(temp));
        }*/
    } else if (strncmp(buf[REQUEST_TYPE], "HEAD", 4) == 0) {
        /* Implement HEAD functionality */
        // At what point in the file does HEAD stop reading? Are there any examples that can be given?
        // ANSWER: Just grab the header information of the file and DO NOT read the content of the file.
        if ((file_fd = open(buf[URL], O_RDONLY)) < 0) {
            if (errno == ENOENT) {
                send_response(clientfd, 404, buffer);
            } else {
                send_response(clientfd, 400, buffer);
            }
        }
        send_response(clientfd, 200, buffer);

    } else {
        /* Might need to figure out how to get size of string array. */
        for (i = 0; i < 7; i++) {
            if(strncmp(buf[REQUEST_TYPE], other_requests[i], 
                strlen(other_requests[i])) == 0) {
                    invalid = 0;
                    send_response(clientfd, 501, buffer);
                }
        }
        if (invalid) send_response(clientfd, 400, buffer);
        /* Child process exits successfully */
    }
    
    if (((strncmp(buf[HTTP_TYPE], "HTTP/1.0", 8) != 0))) {
        send_response(clientfd, 501, buffer);
    }
}

void handle_connection(int socket_fd) {
    int read_val;
    do {
        char buf[BUFSIZ];
        bzero(buf, sizeof(buf));
        if ((read_val = read(socket_fd, buf, BUFSIZ)) < 0) {
           /*send back internal server error (500)*/
           send_response(socket_fd, 500, buf);
        } else {
            parse(buf, socket_fd);
        }
    } while(read_val != 0);
    (void)close(socket_fd);
}

int server_socket_handle() {
    int new_socket;
    pid_t pid;
    
    if ((new_socket = accept(server_socket, (struct sockaddr *)&server,
                            &addrlen)) < 0 && errno != EINTR) {
        fprintf(stderr, "sws: failed to accepted incoming connection. %s.\n",
                strerror(errno));
        return EXIT_FAILURE;
    }
    /* Create child process that handles server socket */
    if ((pid = fork()) < 0) {
        fprintf(stderr, "sws: unable to fork process %s\n", strerror(errno));
        return EXIT_FAILURE;
    } else if(pid == 0) {
        if (alarm(TIMEOUT) == (unsigned int) -1){
            fprintf(stderr, "sws: alarm unable to set timeout %s\n", strerror(errno));
        }

        handle_connection(new_socket);
    }
    /*Wait for client to send a message for a given amount of time (set an alarm before the read)*/
    (void)alarm(0);
    /*If alarm goes off and no read was made, just terminate the connection.*/
    return EXIT_SUCCESS;
}