import ssl
import socket

def get_min_tls(remote_host, port):
    # Loop over TLS versions from highest to lowest
    for tls_version in reversed([ssl.PROTOCOL_TLSv1_2, ssl.PROTOCOL_TLSv1_1, ssl.PROTOCOL_TLSv1]):
        try:
            # Create a socket and wrap it in an SSL context with the current TLS version
            context = ssl.create_default_context()
            context.options |= ssl.OP_NO_TLSv1_3  # disable TLS 1.3 if enabled by default
            context.min_version = tls_version
            with socket.create_connection((remote_host, port)) as sock:
                with context.wrap_socket(sock, server_hostname=remote_host) as ssl_sock:
                    # If the connection succeeds, return the current TLS version as a string
                    return ssl_sock.version()
        except ssl.SSLError:
            # If the connection fails with an SSL error, try the next lower TLS version
            pass

    # If all TLS versions fail, raise an exception
    raise ssl.SSLError("Could not establish a secure connection with any TLS version")

def get_lowest_tls_version(ip, remote_host, port):
    tls_versions = [ssl.PROTOCOL_TLSv1, ssl.PROTOCOL_TLSv1_1, ssl.PROTOCOL_TLSv1_2]
    
    for tls_version in tls_versions:
        try:
            context = ssl.SSLContext(tls_version)
            with socket.create_connection((ip, port)) as sock:
                with context.wrap_socket(sock, server_hostname=remote_host) as ssl_sock:
                    return ssl_sock.version()
        except ssl.SSLError as e:
            if e.reason == "CERTIFICATE_VERIFY_FAILED":
                return "Invalid cert"
            else:
                continue
    return "Unsupported TLS"
