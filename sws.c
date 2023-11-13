#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "util.h"

#define ERROR -1
#define PORT_DEFAULT 8080

static int ip_flags = AF_INET | AF_INET6;

void short_usage() {
    fprintf(stderr, "Usage: sws [-dh] [-c dir] [-i address] [-l file] [-p port] <dir>\n");
}

void usage() {
    (void)printf("Usage: sws [-dh] [-c dir] [-i address] [-l file]");
    (void)printf(" [-p port] <dir>\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        usage();
        exit(EXIT_FAILURE);
    }
    
    char *cgi_dir = NULL;
    char *ip_addr = NULL;
    char *log_file = NULL;
    int cgi = 0, opt = 0, ip = 0, port = 0, help = 0, log = 0, debug = 0;
    int log_fd;

    while ((opt = getopt(argc, argv, "dhc:i:l:p:")) != -1) {
        switch(opt) {
            case 'd':
                debug = 1;
                break;
            case 'h':
                help = 1;
                break;
            case 'c':
                cgi = 1;
                cgi_dir = optarg;
                printf("Execute the CGI here: %s\n", cgi_dir);
                break;
            case 'i':
                ip = 1;
                ip_addr = optarg;
                printf("Get the IPv4/IPv6 address: %s\n", ip_addr);
                break;
            case 'l':
                log = 1;
                log_file = optarg;
                if (log_fd =
                    open(log_file, O_CREAT | O_WRONLY | O_APPEND,
                            S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) < 0) {
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
                if (port < 1024 || port > 65535) {
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

    if (cgi) {
        if (cgi_dir != NULL) check_dir(cgi_dir);
        else {
            fprintf(stderr, "directory path not inputted\n");
            exit(EXIT_FAILURE);
        }
    }

    exit(EXIT_SUCCESS);
}