# sws

sws is a simple web server that speaks a limited version of HTTP/1.0 as defined in RFC1945. It binds to a given port on the given address and waits for incoming HTTP/1.0 requests. It serves content from the given directory.

The code was completed in synchronous collabration between Hiya Bhavsar and Barry Diaz. The two members worked on the code synchrnously and met mutliple times during each week of the project. The project contains the following files: sws.c, sws.h, util.c, utl.h, server.c and server.h.

Key Problems Encountered:
- Understanding the outputs of GET and HEAD
- Understanding the cgi-bin functionality
- Had to adjust already written methods to accomadate changes from new methods (code constantly changing)

sws.c:
- Contains the main method and handles the user inputs
- Initalizes all global variables and error handles any inappropriate inputs
- The server socket is initialized and binded
- The server socket listens for the client (up to 5 connections)
- The server socket handles the connection via the server.c file

sws.h:
- Contains the global variables from sws.c

server.c:
- Handles the server socket and executes the client requests
- The logging, cgi, request functionalities,and HTTP responses are handled within this file
- Problems occurred:
    - parse(1) has to extract the If-Modified-Since for the Conditional GET 
    - Implementing the Conditional GET functionality
        - Comparing the If-Modified-Since dates between the request and the file
    - Setting of cgi-bin environment variables
        - REMOTE_ADDR
        - PATH_INFO
    - Implementing the User Directory when ~ is used
    - Formatting of the logging response when -l flag is invoked
        - Places components of logging response out of order when using sprintf

server.h:
- Contains the header declarations of server.c

util.c:
- Contains additional helper functions used within sws.c and server.c
- Problems Occured
    - The use of realpath within getpath(1)

util.h:
- Contains the header declarations of util.c