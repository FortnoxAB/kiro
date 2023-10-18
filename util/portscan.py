from netaddr import IPNetwork
import socket
import sys
import nmap3  # https://pypi.org/project/python3-nmap/


def portscan(targets):
    result = {}
    try:
        nmap = nmap3.NmapHostDiscovery()
        # Use quick scan for testing! Since time is money
        # nmap_result = nmap.scan_top_ports(' , '.join(targets), args="-sV --open")
        nmap_result = nmap.nmap_portscan_only(' , '.join(targets), args="-sV --open")
        result.update(nmap_result)
    except KeyboardInterrupt:
        print("You pressed Ctrl+C")
        sys.exit()

    except socket.gaierror:
        print("Hostname could not be resolved. Exiting")
        sys.exit()

    except socket.error:
        print("Couldn't connect to server")
        sys.exit()
    return result
