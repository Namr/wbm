#!/usr/bin/python3
import sys
import socket

PORT = 6800
MSG = b'pong\x00'
EXPECTED_LEN = len(MSG)

def main(n: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('localhost', PORT))
    for i in range(n):
        # recv
        bytes_read = 0
        chunks = []
        while bytes_read < EXPECTED_LEN:
            chunk = sock.recv(EXPECTED_LEN)
            bytes_read += len(chunk)
            chunks.append(chunk)
        recv_msg = b''.join(chunks)
        print(recv_msg)

        # send
        sock.send(MSG)

if __name__ == "__main__":
    n = 3
    if len(sys.argv) == 2:
        n = int(sys.argv[1])
    main(n)
