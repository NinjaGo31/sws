#include <sys/stat.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ERROR -1
#define RET_OK 0
#define OK 1

int check_dir(char *path) {
    struct stat sb;
    if (stat(path, &sb) == -1) {
        (void)fprintf(stderr, "stat: path does not exist: %s\n", strerror(errno));
        return ERROR;
    }

    if (S_ISDIR(sb.st_mode) == 0) {
        (void)fprintf(stderr, "stat: given path is not directory: %s\n", strerror(errno));
        return ERROR;
    }

    return RET_OK;
}

int is_int(const char* port) {
    int start = 0;
    int length = strlen(port);

    if (length >= 1 && port[0] == '-') {
        if (length < 2) return ERROR;
        start = 1;
    }

    for (int i = start; i < length; i++)
        if (!isdigit(port[i])) return ERROR;
    
    return OK;
}

int parse_port(const char* input, int* port) {
    long int long_i;

    if (strlen(input) == 0) {
        fprintf(stderr, "sws: No port given\n");
        return ERROR;
    }

    if (is_int(input) && sscanf(input, "%ld", &long_i) == 1) {
        *port = (int)long_i;
        if (long_i != *port) {
            fprintf(stderr, "sws: Integer overflow.\n");
            return ERROR;
        }
    } else {
        fprintf(stderr, "Error: Invalid input '%s' received\n", input);
        return ERROR;
    }

    return RET_OK;
}