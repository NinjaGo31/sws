#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void short_usage() {
    fprintf(stderr, "Usage: sws [-dh] [-i address] [-l file] [-p port] <dir>\n");
}

void usage() {

}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        short_usage();
        exit(EXIT_FAILURE);
    }
    
    int opt;
    int help = 0;
    int debug = 0;

    while ((opt = getopt(argc, argv, "dhc:i:l:p:")) != -1) {
        switch(opt) {
            case 'd':
                debug = 1;
                break;
            case 'h':
                help = 1;
                break;
            case 'c':
                printf("Execute the CGI here: %s\n", optarg);
                break;
            case 'i':
                printf("Get the IPv4/IPv6 address: %s\n", optarg);
                break;
            case 'l':
                printf("Log the requests into here: %s\n", optarg);
                break;
            case 'p':
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

    exit(EXIT_SUCCESS);
}