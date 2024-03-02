#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define PORT 3500

int main(int argc, char** argv) {
  int n = 3;
  if(argc > 1) {
    n = atoi(argv[1]);
  }

  int expected_msg_size = 5;
  char* msg = "pong";

  int socketfd = socket(AF_INET, SOCK_STREAM, 0);
  if(socketfd < 0) {
    printf("Error creating socket, code: %d\n", socketfd);
    return 1;
  }

  struct sockaddr_in server_addr;
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  server_addr.sin_port = htons(PORT);
  if(inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0) {
    printf("Error making an address\n");
    return 1;
  }

  if(connect(socketfd, (struct sockaddr*) &server_addr, sizeof(server_addr)) < 0) {
    printf("Error connecting\n");
    return 1;
  }
  
  char buf[100];
  int bytes_read = 0;
  int buf_len = sizeof(buf);
  for(int i = 0; i < n; i++) {
    while(bytes_read < expected_msg_size) {
      int bytes_read_this_loop = read(socketfd, buf + bytes_read, buf_len);
      bytes_read += bytes_read_this_loop;
      buf_len  -= bytes_read_this_loop;
    }
    printf("message was: %s\n", buf);
    write(socketfd, msg, strlen(msg)+1);

    // reset buf
    bytes_read = 0;
    buf_len = sizeof(buf);
  }

  close(socketfd);
}
