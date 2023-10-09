from util.portscan import *
from util.compare import compare_files_as_json, compare_dicts
from util.dns_enum import dns_enum
from util.domain_checks import run_domain_checks
from util.port_checks import run_port_checks
from util.domaintype import is_subdomain
from util.is_valid_ip import is_valid_ip

import json
import time
import re
import argparse
import socket
import os

def collect_targets(targets):
    expanded_targets = []
    deduplicated_list = []
    enum_domains = []

    for target in targets:
        try:
            for ip in IPNetwork(target): # CDIR and IPs will be added to expanded_targets
                expanded_targets.append(str(ip))
        except: 
            # Check if target is a topdomain, enumerate subdomains and resolve those if so.
            if is_subdomain(target) == False:
                dns_enum_result  = dns_enum(target)
                for domain_item in dns_enum_result:
                    expanded_targets.append(domain_item['address'])
                    enum_domains.append(domain_item)
            # Target is a subdomain, resolve it and add it to targets - perhaps we should enum subdomains as well?
            else:
                for ip in socket.gethostbyname_ex(target)[2]:
                    expanded_targets.append(ip)
                    enum_domains.append({'hostname': target,'address': ip})
    #Remove duplicate IPs from list.
    [deduplicated_list.append(item) for item in expanded_targets if item not in deduplicated_list]
    return deduplicated_list, enum_domains

def cleanup_nmap_object(nmapdata, domains):
    # Remove junk nmap keys
    nmapdata.pop('runtime')
    nmapdata.pop('stats')
    nmapdata.pop('task_results')

    # Loop over keys (IPs) in nmap-result
    for key in nmapdata.keys():
        # Remove empty osmatch key
        nmapdata[key].pop('osmatch')
        nmapdata[key].pop('state')
        nmapdata[key].pop('macaddress')
        if is_valid_ip(key):
            # Flatten nmap reverse-lookups
            if len(nmapdata[key]['hostname']) > 0 and type(nmapdata[key]['hostname'][0]) is dict: 
                nmapdata[key]['hostname'][0] = nmapdata[key]['hostname'][0]['name']
            if len(domains) > 0:
                # Append known domain to hostnames if present
                for domain_item in domains:
                    if key == domain_item['address']:
                        nmapdata[key]['hostname'].append(domain_item['hostname'])
            
            for port in nmapdata[key]['ports']:
                port.pop('state')
                port.pop('reason')
                port.pop('reason_ttl')
                port.pop('cpe')
                port.pop('scripts')
                port['service'].pop('method')
                port['service'].pop('conf')
                try:
                    port['service'].pop('servicefp')
                except:
                    continue
    return nmapdata

def service_main():
    first_run = True
    while True:
        # Store nmapdata from previous run
        if first_run == False:
            previous_nmapdata = nmapdata
        nmapdata = main()
        if first_run == False:
            compare_dicts(previous_nmapdata,nmapdata)
        else:
            # Print scan data
            nmapjson = json.dumps(nmapdata,indent=2)
            print(nmapjson)
        # Sleep for a bit or we will hog CPUs
        time.sleep(os.environ.get('KIRO_INTERVAL',1))
        first_run = False

def main():
    # Collect target_ips
    target_ips, domains = collect_targets(targets)

    # Run nmap portscan
    nmapdata = portscan(target_ips)
    
    # Remove unwanted nmap data from object
    nmapdata = cleanup_nmap_object(nmapdata, domains)  
    nmapdata['flags'] = []  
    nmapdata = run_domain_checks(nmapdata,domains)      
    nmapdata = run_port_checks(nmapdata,domains)

    return nmapdata

# Handle cli arguments
parser = argparse.ArgumentParser(description='Scan networks + domains to assess and improve security posture.')
parser.add_argument("-D", "--daemon",action='store_true', help='Run as service')
parser.add_argument("-H", "--hosts",help="List of hosts separated by commas", type=str)
parser.add_argument("-c", "--compare",action='store_true', help='Compare output to previous file')
parser.add_argument("-f", "--file",action='store_true',help='Write json output to file')
parser.add_argument("-p", "--pretty",action='store_true',help='Prettier output')

args = parser.parse_args()

# Get current datetime
current_date_time = time.strftime("%Y%m%d-%H%M%S")

# Use host argument as target if present else use predefined
if args.hosts:
    targets = args.hosts.split(',')
else:
    try:
        targets = os.environ['KIRO_TARGETS'].split(',') # Swap this to getenv
    except KeyError:
        # No targets specified, exit with error
        print('No targets specified', file=sys.stderr)
        exit(1)

# Check if we're running this as a service, loop if true
if args.daemon or os.environ.get('KIRO_DAEMON','false').lower() == 'true':
    service_main()
else:
    nmapdata = main()
    
    if args.pretty:
        # Print scan data
        nmapjson = json.dumps(nmapdata,indent=2)
    else:
        nmapjson = json.dumps(nmapdata)
    print(nmapjson)

if args.file:
    with open("netmon_" + current_date_time + ".txt", 'w') as fp:
        fp.write(nmapjson)

if args.compare:
    # Complete result is stored into a file. It's time to find
    # and load previous file result to compare with current.
    compare_files_as_json()
