#include <sys/stat.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include "sws.h"

#define ERROR -1
#define RET_OK 0
#define OK 1

int user_dir(char path[], char dirt[]) {
    struct passwd *pwd;
    char *name;
    char *remainder;
    char file[BUFSIZ];
    bzero(file, sizeof(file));
    
    name = strtok(path, "/");
    while ((remainder = strtok(NULL, "/")) != NULL) {
        strncat(file, "/", 1);
        strncat(file, remainder, strlen(remainder));
    }
    strncat(file, "\0", 1);

    if ((pwd = getpwnam(name)) == NULL) {
        return 1;
    }

    strncpy(dirt, pwd->pw_dir, strlen(pwd->pw_dir));
    strncat(dirt, file, strlen(file));
    return 0;
}

char *getpath(char *filename) {
    char buffer[PATH_MAX], fuse_arr[PATH_MAX];
    char *result;
    char *fuse = fuse_arr;
    bzero(fuse_arr, sizeof(fuse_arr));
    
    strncpy(fuse, dir, strlen(dir));
    strncat(fuse, "/", 1);
    strncat(fuse, filename, strlen(filename));

    if ((result = realpath(fuse, buffer)) == NULL) {
        fprintf(stderr, "getpath: failed to make resolved path: %s\n",
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

int is_int(const char* prt) {
    int i;
    int start = 0;
    int length = strlen(prt);

    if (length >= 1 && prt[0] == '-') {
        if (length < 2) return ERROR;
        start = 1;
    }

    for (i = start; i < length; i++)
        if (!isdigit(prt[i])) return ERROR;
    
    return OK;
}

int parse_port(const char* input, int* prt) {
    long int long_i;

    if (strlen(input) == 0) {
        fprintf(stderr, "sws: No port given\n");
        return ERROR;
    }

    if (is_int(input) && sscanf(input, "%ld", &long_i) == 1) {
        *prt = (int)long_i;
        if (long_i != *prt) {
            fprintf(stderr, "sws: Integer overflow.\n");
            return ERROR;
        }
    } else {
        fprintf(stderr, "sws: Invalid input '%s' received\n", input);
        return ERROR;
    }

    return RET_OK;
}

void reap(){
    wait(NULL);
}