#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/param.h>

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
#include "util.h"

#define PARSE_SIZE 4
#define TIMEOUT 60
#define SERVER "Server: sws 1.0\n"
#define CONTENT_TYPE "Content-Type: text/html\n"
#define HTTP "HTTP/1.0 "

enum client_request {REQUEST_TYPE, URI, HTTP_TYPE};

char ** cgi_environment(char **environment, const char *request[], char *query_str){
    int i = 0;
    char port_buf[BUFSIZ];
    char req_buf[BUFSIZ];
    char serv_name[BUFSIZ];
    char script_name[BUFSIZ];
    char query[BUFSIZ];

    if(getsockname(server_socket,(struct sockaddr*) server, &serv_size) == -1){
        fprintf(sterr, "sws: getsockname error: %s\n", strerror(errno));
    }
    
    
    environment[i++] = "AUTH_TYPE=Basic";
    environment[i++] = "GATEWAY_INTERFACE=CGI/1.1";
    environment[i++] = "PATH_INFO="; /*need to implement*/
    sprintf(query, "QUERY_STRING=%s\n", query_str);
    environment[i++] = query;
    environment[i++] = "REMOTE_ADDR="; /*need to implement*/
    sprintf(req_buf, "REQUEST_METHOD=%s\n", request[REQUEST_TYPE]);
    environment[i++] = req_buf;
    sprintf(script_name, "SCRIPT_NAME=%s\n", request[URI]);
    environment[i++] = script_name;
    sprintf(serv_name, "SERVER_NAME=%s\n", inet_ntoa(server.sin_addr));
    environment[i++] = serv_name;
    sprintf(port_buf, "SERVER_PORT=%d\n", ntohs(server.sin_port));
    environment[i++] = port_buf;
    environment[i++] = "SERVER_PROTOCOL=HTTP/1.0";
    environment[i++] = "SERVER_SOFTWARE="; /*need to implement*/

}
void exec_cgi(int clientfd, const char* request, char *query_str) {
    int fdout[2];
    int fderr[2];
    char *outbuf[BUFSIZ];
    char *errbuf[BUFSIZ]; 
    char *executable[BUFSIZ];
    char *environment[12];
    pid_t pid;

    if (pipe(fdout) < 0) {
        (void)fprintf(stderr, "sws: pipe : %s\n", strerror(errno));
        send_response(clientfd, 500, request);
    }

    if (pipe(fderr) < 0) {
        (void)fprintf(stderr, "sws: pipe : %s\n", strerror(errno));
        send_response(clientfd, 500, request);
    }
    /*set environment*/

    /*not sure if signals are needed*/
    if ((pid = fork()) < 0) {
        (void)fprintf(stderr, "sws: fork : %s\n", strerror(errno));
        send_response(clientfd, 500, request);
    }

    if (pid > 0) {
        /*parent process*/
        /*close write ends*/
        (void)close(fdout[1]);
        (void)close(fderr[1]);

        if ((n = read(fdout[0], outbuf, outlen)) < 0)
        {
            (void)fprintf(stderr, "sws: Unable to read from pipe: %s\n", strerror(errno));
            send_response(clientfd, 500, request);
        }

        if ((n = read(fderr[0], errbuf, errlen)) < 0)
        {
            (void)fprintf(stderr, "sws: Unable to read from pipe: %s\n", strerror(errno));
            send_response(clientfd, 500, request);
        }
        /*close read ends*/
        (void)close(fdout[0]);
        (void)close(fderr[0]);

        if (waitpid(pid, NULL, 0) < 0)
        {
            (void)fprintf(stderr, "sws: waitpid: %s\n", strerror(errno));
            send_response(clientfd, 500, request);
        }
    }else{
        /*child process*/
        /*close read ends*/
        (void)close(fdout[0]);
        (void)close(fderr[0]);

        if (dup2(fdout[1], STDOUT_FILENO) < 0){
            (void)fprintf(stderr, "sws: dup2 to stdout: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }

        if (dup2(fderr[1], STDERR_FILENO) < 0){
            (void)fprintf(stderr, "sws: dup2 to stderr: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }

        if (chdir(cgi_dir) < 0){
            (void)fprintf(stderr, "sws: could not change to directory: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }
        /*need to implement execvpe*/

        /*close write ends*/
        (void)close(fdout[1]);
        (void)close(fderr[1]);
    
    }
}

void logging(int ip_addr, char err_time_buf, const char *request, int code, char content_len){
    char log_output[BUFSIZ];
    int nr;

    sprintf(log_output, "%d %s \"%s\" %d %c\r\n", ip_addr, err_time_buf, request, code, content_len);

    if(debug){
        fprintf(stdout, "%d %s \"%s\" %d %c\r\n", ip_addr, err_time_buf, request, code, content_len);
    }
    else if(l_flag){
        if((nr = write(log_fd, log_output, sizeof(log_output))) < 0){
            fprintf(stderr, "sws: failed to write to log. %s.\n",
                strerror(errno));
        }
    }

}

void send_response(int clientfd, int code, const char *request[]) {
    char* status_str;
    char log_info[BUFSIZ];
    time_t curr_time;
    time_t err_time;
    char general_info[BUFSIZ];
    char time_buf[BUFSIZ];
    char err_time_buf[BUFSIZ]
    char last_mod_buf[BUFSIZ];
    char content_len[BUFSIZ];
    struct tm gmt;
    struct stat last_mod;
    int error_flag = 0;
    int ip_addr;

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

   
    /*send date*/
    time(&curr_time);
    gmt = *gmtime(&curr_time);
    strftime(time_buf, sizeof(time_buf), "Date: %A, %d %B %Y %H:%M:%S GMT\r\n", &gmt);
    send(clientfd, time_buf, strlen(time_buf),0);

    /*send server*/
    send(clientfd, SERVER, strlen(SERVER), 0);

    /*send last modified*/
    stat(request[URI], &last_mod);
    gmt = *gmtime(&last_mod.st_mtime);
    strftime(last_mod_buf, sizeof(last_mod_buf), "Last-Modified: %A, %d %B %Y %H:%M:%S GMT\r\n", &gmt);
    send(clientfd, last_mod_buf, strlen(last_mod_buf), 0);
    
    /*send content type*/
    send(clientfd, CONTENT_TYPE, strlen(CONTENT_TYPE), 0);

    /*send content length*/
    if(error_flag == 1){
        sprintf(content_len, "Content-Length: 0\r\n");
    }else{
        sprintf(content_len, "Content-Length: %ld\r\n", last_mod.st_size);
    }
    send(clientfd, content_len, sizeof(content_len), 0);

    if (l_flag && log_fd > 0 || debug) {
        /*get IP address*/
        ip_addr = inet_ntop(server.sin_addr);
        /*time request was recieved*/
        time(&err_time);
        gmt = *gmtime(&err_time);
        strftime(err_time_buf, sizeof(err_time_buf), "%Y-%B-%dT%H:%M:%SZ\r\n", &gmt);
        /* Enter logging function */
        logging(ip_addr, err_time_buf, request, code, content_len);   
    }

    if (strncmp(request[REQUEST_TYPE], "GET", 3) == 0) {
        // Read the file back to the client
    }
}

void parse(char buffer[], int clientfd) {
    char *other_requests[] = {"POST", "PUT", "DELETE", "CONNECT", 
                                "OPTIONS", "TRACE", "PATCH"};
    char *buf[BUFSIZ], *lines[BUFSIZ];
    char *client_dir, *query_str, *tmp;
    char *arg, *traverse, *line, *nul;

    int i, file_fd;
    int error = 0, invalid = 1, query_flag = 0, mod_since = 0;
    size_t arr_len = sizeof(other_requests) / sizeof(other_requests[0]);
    size_t size = strlen(buffer);

    struct tm time_req;
    memset(&time_req, 0, sizeof(time_req));

    traverse = buffer;
    i = 0;
    while((traverse < buffer + size) &&
            ((nul = strstr(traverse, "\n")) != NULL)) {
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
    
    buf[URI] = strtok(buf[URI], "?");
    tmp = strtok(NULL, "?");
    if (tmp != NULL) query_str = tmp;

    if (lines[1] != NULL) {
        arg = strtok(lines[1], ":");
        if (strncmp(arg, "If-Modified-Since") != 0) {
            send_response(clientfd, 400, buf);
        } else {
            mod_since = 1;
            arg = strtok(NULL, ":");
            strptime(arg, "%A, %d %m %Y %H:%M:%S", &time_req);
        }
    }

    if ((client_dir = getpath(buf[URI])) == NULL) {
        if (errno == ENOENT) send_response(clientfd, 404, buf);
        else send_response(clientfd, 400, buf);
    } else if (strncmp(dir, client_dir, strlen(dir)) != 0) {
        send_response(clientfd, 403, buf);
    }

    if ((strncmp(buf[REQUEST_TYPE], "GET", 3) == 0)) {
        /* Implement GET functionality */
        // What errors are we supposed to catch in the GET/HEAD event? How do we handle them?
        // - The files doesn't exist at all (Send 404)
        // - The file exists, but the client doesn't have access to the file (Send either 401 or 403)
        // - The client's request is OUTSIDE of docroot (Send 403)
        // /home/<user>/sws --> /docroot

        // How can we keep track of where the client is trying to access? Parse by '/' and
        // keep tally of the name of the directory location?
        // ANSWER: Construct an absolute/real path with the docroot path and client path,
        // and then check if the resulting path is under the docroot
        // USE THE realpath(3) function. Must be under the docroot path.
        // Do we hard code the docroot path?
        // No. The last argument is the directory in which you are serving content from. In this case,
        // create an absolute path using this argument.
        if ((file_fd = open(buf[URI], O_RDONLY)) < 0) {
            if (errno == ENOENT) {
                error = 1;
                send_response(clientfd, 404, buf);
            } else {
                error = 1;
                send_response(clientfd, 400, buf);
            }
        }
    } else if (strncmp(buf[REQUEST_TYPE], "HEAD", 4) == 0) {
        if ((file_fd = open(buf[URI], O_RDONLY)) < 0) {
            if (errno == ENOENT) {
                error = 1;
                send_response(clientfd, 404, buf);
            } else {
                error = 1;
                send_response(clientfd, 400, buf);
            }
        }
    } else {
        for (i = 0; i < arr_len; i++) {
            if(strncmp(buf[REQUEST_TYPE], other_requests[i], 
                strlen(other_requests[i])) == 0) {
                    invalid = 0;
                    error = 1;
                    send_response(clientfd, 501, buf);
                    break;
            }
        }
        if (invalid) {
            error = 1
            send_response(clientfd, 400, buf);
        }
        /* Child process exits successfully */
    }
    
    if ((strncmp(buf[HTTP_TYPE], "HTTP/1.0", 8) != 0)) {
        invalid = 0;
        send_response(clientfd, 501, buf);
    }
    if (!invalid) send_response(clientfd, 200, buf);
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
        if (alarm(TIMEOUT) == (unsigned int) -1) {
            fprintf(stderr, "sws: alarm unable to set timeout %s\n", strerror(errno));
        }

        handle_connection(new_socket);
    }
    /*Wait for client to send a message for a given amount of time (set an alarm before the read)*/
    (void)alarm(0);
    /*If alarm goes off and no read was made, just terminate the connection.*/
    return EXIT_SUCCESS;
}
