from netaddr import IPNetwork
import socket
import subprocess
import sys
import nmap3 #https://pypi.org/project/python3-nmap/
from os import access, R_OK
from os.path import isfile

def dns_enum(target, wordlist):
    nmap = nmap3.Nmap()
    assert isfile(wordlist) and access(wordlist, R_OK), \
        f"Wordlist {wordlist} doesn't exist or isn't readable"
    results = nmap.nmap_dns_brute_script(target, dns_brute="--script dns-brute.nse --script-args dns-brute.hostlist=" + wordlist)
    # Add any A-records for the original target as well.
    try:
        for ip in socket.gethostbyname_ex(target)[2]:
            results.append({'hostname': target,'address': ip})
    except:
        return results
    return results