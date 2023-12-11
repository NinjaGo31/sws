#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include "server.h"
#include "sws.h"
#include "util.h"

#define PORT_DEFAULT    8080

static const char help_str[] = 
    " ./sws [-dh] [-i address] [-l file] [-p port number] dir\n"
    " -d                Enter debug mode\n"
    " -h                Print this help message\n"
    " -i address        Make server on this IPv4/IPv6 address\n"
    " -l file           Log entries into file\n"
    " -p port number    Make server on this port\n"
    ;

char *cgi_dir = NULL;
char *dir = NULL;
char *log_file = NULL;

int domain = AF_INET6;
int server_socket = -1;
int num = 0;
int c_flag = 0, l_flag = 0, debug = 0;
int port;
socklen_t addrlen, serv_size;

void short_usage() {
    fprintf(stderr, "Usage: sws [-dh] [-c dir] [-i address] [-l file] [-p port] <dir>\n");
}

void usage() {
    (void)printf("%s", help_str);
}

void cleaning() {
    int i;
    if (fcntl(server_socket, F_GETFD) >= 0) close(server_socket);

    for (i = 0; i < CONNECTIONS; i++) {
        if (fcntl(client_sockets[i], F_GETFD) >= 0)
            close(client_sockets[i]);
    }
}

int main(int argc, char* argv[]) {
    char *ip_addr = NULL;

    int opt = 0, ip = 0, help = 0;
    int running = 1;
    int exitval = EXIT_SUCCESS;
    /*int log_fd;*/
    int i;
    int max_socket;
    fd_set sockset;

    struct sockaddr_in server4;
    struct sockaddr_in6 server6;

    if (argc < 2) {
        usage();
        exit(EXIT_FAILURE);
    }

    while ((opt = getopt(argc, argv, "dhc:i:l:p:")) != -1) {
        switch(opt) {
            case 'd':
                debug = 1;
                break;
            case 'h':
                help = 1;
                break;
            case 'c':
                c_flag = 1;
                cgi_dir = optarg;
                check_dir(cgi_dir);
                printf("Execute the CGI here: %s\n", cgi_dir);
                break;
            case 'i':
                ip = 1;
                ip_addr = optarg;
                printf("Get the IPv4/IPv6 address: %s\n", ip_addr);
                break;
            case 'l':
                l_flag = 1;
                log_file = optarg;
                if ((log_fd =
                    open(log_file, O_CREAT | O_WRONLY | O_APPEND,
                            S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0) {
                    fprintf(stderr, "sws: file could not be opened: %s\n",
                            strerror(errno));
                    exit(EXIT_FAILURE);
                }
                printf("Log the requests into here: %s\n", log_file);
                break;
            case 'p':
                if ((parse_port(optarg, &port) == ERROR)) {
                    exit(EXIT_FAILURE);
                }
                if (port < 0 || port > 65535) {
                    fprintf(stderr, "sws: Port number must be in range [1024, 65535]\n");
                    exit(EXIT_FAILURE);
                }
                printf("Here's the port number: %s\n", optarg);
                break;
            case '?':
                fprintf(stderr, "sws: unknown option: %c\n", optopt);
                short_usage();
                exit(EXIT_FAILURE);
        }
    }

    argc -= optind;
    argv += optind;
    
    if (help) {
        usage();
        exit(EXIT_SUCCESS);
    }
    
    if ((dir = getpath(argv[optind])) == NULL) {
        exitval = EXIT_FAILURE;
        cleaning();
        exit(exitval);
    }

    /* Any number other than 0 is considered TRUE */
    if (!port) port = PORT_DEFAULT;

    if (ip) {
        if (ip_addr != NULL) {
            if (inet_pton(AF_INET, ip_addr, &(server4.sin_addr)) == 1) {
                domain = AF_INET;
            } else {
                if (inet_pton(AF_INET6, ip_addr, &(server6.sin6_addr)) <= 0) {
                    fprintf(stderr, "sws: invalid IP address '%s'\n", ip_addr);
                    exit(EXIT_FAILURE);
                }
            }
        }
    }

    if (debug) {
        printf("Debugging mode\n");
    } else {
        if(daemon(1,0) < 0) {
            fprintf(stderr, "sws: daemon\n");
            exit(EXIT_FAILURE);
        }
    }
    
    if (domain == AF_INET) {
        addrlen = sizeof(server4);
        memset(&server4, 0, sizeof(addrlen));

        server4.sin_family = AF_INET;
        server4.sin_addr.s_addr = INADDR_ANY;
        server4.sin_port = htons(port);
        server = &server4;
        serv_size = sizeof(server4);
    } else {
        addrlen = sizeof(server6);
        memset(&server6, 0, sizeof(addrlen));

        server6.sin6_family = AF_INET6;
        server6.sin6_addr = in6addr_any;
        server6.sin6_port = htons(port);
        server = &server6;
        serv_size = sizeof(server6);

        if (!ip) {
            int offset = 0;
            if (setsockopt(server_socket, IPPROTO_IPV6, IPV6_V6ONLY,
                    (void *)&offset, sizeof(offset)) < 0) {
                fprintf(stderr, "sws: failed to set socket options: %s",
                        strerror(errno));
                exitval = EXIT_FAILURE;
                cleaning();
                exit(exitval);
            }
        }
    }

    if (bind(server_socket, (struct sockaddr *)&server, serv_size) < 0) {
        fprintf(stderr, "sws: failed to bind socket to port %d. %s.\n",
                port, strerror(errno));
        exitval = EXIT_FAILURE;
        cleaning();
    }

    for (i = 0; i < CONNECTIONS; i++) client_sockets[i] = -1;

    if (listen(server_socket, CONNECTIONS) < 0) {
        exitval = EXIT_FAILURE;
        cleaning();
        exit(exitval);
    }
    if(signal(SIGCHLD, reap) == SIG_ERR){
        fprintf(stderr, "sws: signal() failed\n");
        return EXIT_FAILURE;
    }

    while(running) {
        FD_ZERO(&sockset);
        FD_SET(server_socket, &sockset);
        max_socket = server_socket;

        for (i = 0; i < CONNECTIONS; i++) {
            if (client_sockets[i] > -1) FD_SET(client_sockets[i], &sockset);
            if (client_sockets[i] > max_socket) max_socket = client_sockets[i];
        }

        if (select(max_socket + 1, &sockset, NULL, NULL, NULL) < 0 
                && errno != EINTR) {
            fprintf(stderr, "sws: select() failed. %s.\n", strerror(errno));
            close(server_socket);
            exitval = EXIT_FAILURE;
            cleaning();
            exit(exitval);
        }

        if (running && FD_ISSET(server_socket, &sockset)) {
            /* Handle server socket */
            if(server_socket_handle() == EXIT_FAILURE) {
                exitval = EXIT_FAILURE;
                cleaning();
                exit(exitval);
            }
        }
        
    }

    cleaning();
    exit(exitval);
}