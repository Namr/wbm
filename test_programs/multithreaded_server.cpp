#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <thread>
#include <iostream>
#include <vector>

#define PORT 6800

int main(int argc, char** argv) {
  int n = 3;
  if(argc > 1) {
    n = atoi(argv[1]);
  }

  int expected_msg_size = 5;
  char* msg = "ping";

  struct sockaddr_in my_addr;
  int socketfd = socket(AF_INET, SOCK_STREAM, 0);
  my_addr.sin_family = AF_INET;
  my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  my_addr.sin_port = htons(PORT);

  bind(socketfd, (struct  sockaddr*) &my_addr, sizeof(my_addr));
  listen(socketfd, 10);
  
  int clientfd;
  std::vector<std::thread> threads;
  while(1) {
    clientfd = accept(socketfd, NULL, NULL);
    
    // spin a thread to talk to this client
    std::thread ping_thread([clientfd, n, expected_msg_size, &msg] {
      char buf[100];
      int bytes_read = 0;
      int buf_len = sizeof(buf);
      for(int i = 0; i < n; i++) {
        write(clientfd, msg, strlen(msg)+1);

        while(bytes_read < expected_msg_size) {
          int bytes_read_this_loop = read(clientfd, buf + bytes_read, buf_len);
          bytes_read += bytes_read_this_loop;
          buf_len  -= bytes_read_this_loop;
        }

        std::cout << "message was: " << buf << std::endl;

        // reset buf
        bytes_read = 0;
        buf_len = sizeof(buf);
      }

      std::cout << "thread terminating\n";
    });
    threads.push_back(std::move(ping_thread));

    sleep(1);
  }
}
