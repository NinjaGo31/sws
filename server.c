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

#include "sws.h"

#define PARSE_SIZE 4

enum client_request {REQUEST_TYPE, URL, HTTP_TYPE};

void parse(char* buffer) {
    char *b[PARSE_SIZE];
    int i;
    
    char* arg = strtok(buffer, " ");
    while(arg != NULL) {
        b[i++] = arg;
        arg = strtok(NULL, " ");
    }
    b[i] = NULL;

    if (((strncmp(b[REQUEST_TYPE], "GET", 3) != 0) || 
            (strncmp(b[REQUEST_TYPE], "HEAD", 4) != 0))) {
        /* Send back bad request code (400) */
        /* Child process exits successfully */
    }
    
    if (((strncmp(b[HTTP_TYPE], "HTTP/1.0", 8) != 0))) {
        /* Send back bad request code (400) */
    }
}

void handle_connection(int socket_fd, struct sockaddr* client){
    int read_val;
    int i = 0;
    do {
        char buf[BUFSIZ];
        bzero(buf, sizeof(buf));
        if ((read_val = read(socket_fd, buf, BUFSIZ)) < 0) {
           /*send back internal server error (500)*/
        } else {
            parse(buf);
        }
    } while(read_val != 0);
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
    if((pid = fork())<0){
        fprintf(stderr, "sws: unable to fork process %s\n", strerror(errno));
        return EXIT_FAILURE;
    }else if(pid == 0){
        handle_connection(new_socket, server);
    }
    // Wait for client to send a message for a given amount of time (set an alarm before the read)
    // If alarm goes off and no read was made, just terminate the connection.
    return EXIT_SUCCESS;
}