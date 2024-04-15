#!/usr/bin/python3
import sys
import socket
import threading

PORT = 6800
MSG = b"pong\x00"
EXPECTED_LEN = len(MSG)


def socket_client(n: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("localhost", PORT))
    for i in range(n):
        # recv
        bytes_read = 0
        chunks = []
        while bytes_read < EXPECTED_LEN:
            chunk = sock.recv(EXPECTED_LEN)
            bytes_read += len(chunk)
            chunks.append(chunk)
        recv_msg = b"".join(chunks)
        print(recv_msg)

        # send
        sock.send(MSG)


def busy_work():
    sum = 1
    neg = 1
    for i in range(100000000):
        sum += i * 2
        neg -= i * sum
    print(f"{sum}")


def main(n: int):
    socket_thread = threading.Thread(target=socket_client, args=(n,))
    busy_thread = threading.Thread(target=busy_work)
    socket_thread.start()
    busy_thread.start()
    busy_work()
    socket_thread.join()
    busy_thread.join()


if __name__ == "__main__":
    n = 3
    if len(sys.argv) == 2:
        n = int(sys.argv[1])
    main(n)
