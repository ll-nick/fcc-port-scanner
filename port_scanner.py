import socket
import nmap
from common_ports import ports_and_services

def get_open_ports(target, port_range, verbose = False):
    target_ip = None
    target_host = None

    if is_ip(target):
        if not is_valid_ip(target):
            return 'Error: Invalid IP address'
        try:
            target_ip = target
            target_host = socket.gethostbyaddr(target_ip)[0]
        except:
            target_host = None
    else:
        try:
            target_host = target
            target_ip = socket.gethostbyname(target_host)
        except socket.error:
            return 'Error: Invalid hostname'

    nm = nmap.PortScanner()
    nm.scan(target_ip, arguments=f'-p{port_range[0]}-{port_range[1]}')

    open_ports = []
    for port in range(port_range[0], port_range[1] + 1):
        if 'tcp' in nm[target_ip] and port in nm[target_ip]['tcp'] and nm[target_ip]['tcp'][port]['state'] == 'open':
            open_ports.append(port)

    if verbose:
        if target_host:
            host_info = f"{target_host} ({target_ip})"
        else:
            host_info = target_ip
        
        result = f"Open ports for {host_info}\nPORT     SERVICE\n"
        for port in open_ports:
            service_name = ports_and_services.get(port, "Unknown")
            result += f"{port:<9}{service_name}\n"
        
        return result.strip()
    else:
        return open_ports

def is_ip(ip):
    return not ip.split('.')[-1].isalpha()

def is_valid_ip(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or int(part) < 0 or int(part) > 255:
            return False
    return True