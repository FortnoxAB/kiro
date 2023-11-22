from netaddr import IPNetwork
import socket
import sys
import nmap3  # https://pypi.org/project/python3-nmap/


def portscan(targets):
    result = {}
    try:
        nmap = nmap3.Nmap()
        nmap_result = nmap.nmap_version_detection(' , '.join(targets),
                                                  args="-sV --open --script vulners --script-args mincvss=5.0")
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
