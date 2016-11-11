#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/time.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>


int main(int argc, char** argv) {
    // argument checking
    if(argc < 3) {
        printf("Usage: %s host port message", argv[0]);
        return 0;
    }

    struct sockaddr_in host;
    char* message = argv[3];

    if(!message) {
        puts("I can't send an empty message, please send some value!");
        return 0;
    }
    int socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (socket_fd < 0) {
        perror("Unable to create socket");
        return 0;
    }

    int on = 1;
    if(setsockopt(socket_fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)) < 0) {
        perror("Unable to set socket options");
        return 0;
    }

    // set up the connection
    int port = atoi(argv[2]);

    host.sin_addr.s_addr = inet_addr(argv[1]);
    host.sin_family = AF_INET;
    host.sin_port = htons(port);

    // connect to our server and start sending goodies.
    if(connect(socket_fd, (struct sockaddr*) &host, sizeof(host)) < 0) {
        perror("Unable to connect");
        return 0;
    }

    // send a host of packets / messages to the server.
    while(1) {
        if(send(socket_fd, message, strlen(message), MSG_NOSIGNAL) < 0) {
            perror("Send message failed");
            break;
        }
        else {
            printf("Sent message: %s to %s \n", message, argv[1]);
        }
    }
    close(socket_fd);
    return 0;
}


