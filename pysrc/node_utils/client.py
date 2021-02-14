import socket
import sys
import time

HOST, PORT = "localhost", 8000
data = b" "
TIMEOUT = 40.0


if __name__ == '__main__':
    if len(sys.argv) != 5:
        print("Usage: ./client <SERVER ADDRESS> <PORT> <EXPECTED RESPONSE> <UDP/TCP>")
        sys.exit(1)

    EXPECTED_RESPONSE = sys.argv[3]
    PORT = int(sys.argv[2])
    HOST = sys.argv[1]
    udp = False
    if sys.argv[4] == "UDP":
        udp = True

    start_time = time.time()
    while time.time() - start_time < TIMEOUT:
        try:
            if udp:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(0.1)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(TIMEOUT)
            # sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # sock.bind(("", 44444))
            if not udp:
                sock.connect((HOST, PORT))
            print("Connected!")
            if udp:
                sock.sendto(data, (HOST, PORT))
            else:
                sock.sendall(data)
            print("Data sent!")

            if udp:
                received, _ = sock.recvfrom(1024)
            else:
                received = sock.recv(1024)
            print("Data received!")
            break
        except socket.error as e:
            pass
            print(e)
        finally:
            sock.close()

    if data == "kill":
        print("Server was hopefully killed.")
        sys.exit(0)

    try:
        print("Received: {}".format(received))
        if EXPECTED_RESPONSE.encode("utf-8") != received:
            print("Response did not match expectations!")
            sys.exit(2)
        print("Response matched expectation.")
        sys.exit(0)
    except NameError:
        sys.exit(3)