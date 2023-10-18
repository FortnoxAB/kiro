import socket
import ssl


def check_http(ip, domain, port):
    httpget = "GET / HTTP/1.1\r\nHost: " + domain + "\r\n\r\n"

    try:
        # Try HTTP connection
        http_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        http_sock.settimeout(2)
        http_sock.connect((ip, int(port)))
        http_sock.sendall(httpget.encode())
        http_response = http_sock.recv(1024).decode()
        http_sock.close()

        if "HTTP/" in http_response:
            return "HTTP"

        # Try HTTPS connection
        https_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        https_sock.settimeout(2)
        https_sock.connect((ip, int(port)))
        context = ssl.create_default_context()
        with context.wrap_socket(https_sock, server_hostname=domain) as secure_sock:
            secure_sock.sendall(httpget.encode())
            https_response = secure_sock.recv(1024).decode()

        if "HTTP/" in https_response:
            return "HTTPS"

    except:
        pass

    return "Neither"
