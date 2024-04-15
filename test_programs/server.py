#!/usr/bin/python3
import sys
import socket

PORT = 6800
MSG = b"ping\x00"
EXPECTED_LEN = len(MSG)


def main(n: int):
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind(("localhost", PORT))
    serversocket.listen(1)

    while True:
        (client_socket, address) = serversocket.accept()
        for i in range(n):
            # send
            client_socket.send(MSG)

            # recv
            bytes_read = 0
            chunks = []
            while bytes_read < EXPECTED_LEN:
                chunk = client_socket.recv(EXPECTED_LEN)
                bytes_read += len(chunk)
                chunks.append(chunk)
            recv_msg = b"".join(chunks)
            print(recv_msg)


if __name__ == "__main__":
    n = 3
    if len(sys.argv) == 2:
        n = int(sys.argv[1])
    main(n)
