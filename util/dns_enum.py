from netaddr import IPNetwork
import socket
import subprocess
import sys
import nmap3 #https://pypi.org/project/python3-nmap/

def dns_enum(target):
    nmap = nmap3.Nmap()
    results = nmap.nmap_dns_brute_script(target, dns_brute="--script dns-brute.nse --script-args dns-brute.hostlist=./subdomains.txt")
    # Add any A-records for the original target as well.
    try:
        for ip in socket.gethostbyname_ex(target)[2]:
            results.append({'hostname': target,'address': ip})
    except:
        return results
    return results