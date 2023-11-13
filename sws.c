#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>

void check_dir(char *path)
{
    struct stat *sb;
    if (stat(path, sb) == -1)
    {
        (void)fprintf(stderr, "stat: path does not exist: %s\n", sterror(errno));
        exit(EXIT_FAILURE);
    }
    if (S_ISDIR(sb->st_mode) == 0)
    {
        (void)fprintf(stderr, "stat: given path is not directory: %s\n", sterror(errno));
        exit(EXIT_FAILURE);
    }
}
void short_usage()
{
    fprintf(stderr, "Usage: sws [-dh] [-i address] [-l file] [-p port] <dir>\n");
}

void usage()
{
    (void)printf("Usage: sws [-dh] [-i address] [-l file] [-p port] <dir>\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        short_usage();
        exit(EXIT_FAILURE);
    }

    int opt;
    int help = 0;
    int debug = 0;
    int cgi = 0;
    int ipv = 0;
    int log = 0;
    int port = 0;

    char *cgi_dir = NULL;
    char *ipv_address = NULL;
    char *log_file = NULL;
    int port_num = 8080;

    int log_fd;

    while ((opt = getopt(argc, argv, "c:dhi:l:p:")) != -1)
    {
        switch (opt)
        {
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
            ipv = 1;
            ipv_address = optarg;
            printf("Get the IPv4/IPv6 address: %s\n", ipv_address);
            break;
        case 'l':
            log = 1;
            log_file = optarg;
            printf("Log the requests into here: %s\n", log_file);
            break;
        case 'p':
            port = 1;
            port_num = atoi(optarg);
            printf("Here's the port number: %s\n", port_num);
            break;
        case '?':
            fprintf(stderr, "sws: unknown option: %c\n", optopt);
            short_usage();
            exit(EXIT_FAILURE);
        }
    }
    argc -= optind;
    argv += optind;

    if (help)
    {
        usage();
        exit(EXIT_SUCCESS);
    }

    if (cgi)
    {
        if (cgi_dir != NULL)
        {
            check_dir(cgi_dir);
        }
        else
        {
            fprintf(stderr, "directory path not inputted\n");
            exit(EXIT_FAILURE);
        }
    }
    if (port)
    {
        if (port_num < 1024 || port_num > 65535)
        {
            fprintf(stderr, "port number is invalid\n");
            exit(EXIT_FAILURE);
        }
    }
    if (log)
    {
        if (log_file != NULL)
        {
            if (log_fd = open(log_file, O_CREAT | O_WRONLY | O_APPEND) < 0)
            {
                fprintf(stderr, "file could not be opened: %s\n", sterror(errno));
                exit(EXIT_FAILURE);
            }
        }
    }

    if (ipv)
    {
    }

    exit(EXIT_SUCCESS);
}