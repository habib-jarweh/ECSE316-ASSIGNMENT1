import socket

def is_valid_server_address(arg, port, timeout):
    if arg[0] != "@": return False

    dns_server = arg[1:]

    try:
        # Create a socket to the DNS server
        socket.create_connection((dns_server, port), timeout)
        return True
    except (socket.error, OSError):
        return False

def is_valid_hostname(hostname):
    try:
        socket.gethostbyname(hostname)
        return True
    except socket.error:
        return False