#include <sys/stat.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#define ERROR -1
#define RET_OK 0
#define OK 1

void user_dir(char path[], char dir[]) {
    struct passwd *pwd;
    char *name;
    char *remainder;
    char file[BUFSIZ];
    bzero(file, sizeof(file));
    path += 2;
    
    name = strtok(path, "/");
    while ((remainder = strtok(NULL, "/")) != NULL) {
        strncat(file, "/", 1);
        strncat(file, remainder, strlen(remainder));
    }
    strncat(file, "\0", 1);

    if ((pwd = getpwnam(name)) == NULL) {
        perror("getpwnam() error");
    }

    strncpy(dir, pwd->pw_dir, strlen(pwd->pw_dir));
    strncat(dir, file, strlen(file));
}

char *getpath(char *dir) {
    char buffer[PATH_MAX];
    char *result;

    if (dir[0] != '/') return NULL;
    else dir++;

    if ((result = realpath(dir, buffer)) == NULL) {
        fprintf(stderr, "sws: failed to make resolved path: %s\n",
                strerror(errno));
        return NULL;
    }

    return result; 
}

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
    int i;
    int start = 0;
    int length = strlen(port);

    if (length >= 1 && port[0] == '-') {
        if (length < 2) return ERROR;
        start = 1;
    }

    for (i = start; i < length; i++)
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

void reap(){
    wait(NULL);
}