import sys
import socket
import time

PORT = 8000
response = "default"
TIMEOUT = 40.0

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: ./server <PORT> <HOSTNAME> <UDP/TCP>")
        sys.exit(1)

    PORT = int(sys.argv[1])
    response = sys.argv[2]
    udp = False
    if sys.argv[3] == "UDP":
        udp = True

    if udp:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(TIMEOUT)
    s.bind(("", PORT))
    if not udp:
        s.listen()
        conn, addr = s.accept()
        print('Connected by', addr)
    print("{host} serving at port {port}".format(
        host=response,
        port=PORT
    ))
    start_time = time.time()
    while time.time() - start_time < TIMEOUT:
        if udp:
            data, address = s.recvfrom(1024)
            if not data:
                break
            s.sendto(response.encode("utf-8"), address)
            print("Responding to {host}:{port}".format(
                host=address[0],
                port=address[1]
            ))
            break
        else:
            data = conn.recv(1024)
            if not data:
                break
            conn.sendall(response.encode("utf-8"))
            print("Responding to {host}:{port}".format(
                host=addr[0],
                port=addr[1]
            ))
            break

    if not udp:
        conn.close()
    s.close()