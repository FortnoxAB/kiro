from typing import Dict, Any

from util.portscan import *
from util.compare import compare_files_as_json, compare_dicts
from util.dns_enum import dns_enum
from util.domain_checks import run_domain_checks
from util.port_checks import run_port_checks
from util.domaintype import is_subdomain
from util.is_valid_ip import is_valid_ip

import json
import time
import argparse
import socket
import os


def collect_targets(target_list):
    expanded_targets = []
    deduplicated_list = []
    enum_domains = []

    for target in target_list:
        try:
            for ip in IPNetwork(target):  # CDIR and IPs will be added to expanded_targets
                expanded_targets.append(str(ip))
        except:
            # Check if target is a top domain, enumerate subdomains and resolve those if so.
            if not is_subdomain(target):
                if args.wordlist:
                    dns_enum_result = dns_enum(target, args.wordlist)
                else:
                    dns_enum_result = dns_enum(target, "./subdomains.txt")
                for domain_item in dns_enum_result:
                    expanded_targets.append(domain_item['address'])
                    enum_domains.append(domain_item)
            # Target is a subdomain, resolve it and add it to targets - perhaps we should enum subdomains as well?
            else:
                for ip in socket.gethostbyname_ex(target)[2]:
                    expanded_targets.append(ip)
                    enum_domains.append({'hostname': target, 'address': ip})

    # Remove duplicate IPs from list.
    [deduplicated_list.append(item) for item in expanded_targets if item not in deduplicated_list]
    return deduplicated_list, enum_domains


def cleanup_nmap_object(nmap_object, domains):
    # Remove junk nmap keys
    nmap_object.pop('runtime')
    nmap_object.pop('stats')
    nmap_object.pop('task_results')

    # Loop over keys (IPs) in nmap-result
    for key in nmap_object.keys():
        # Remove junk nmap keys
        nmap_object[key].pop('osmatch')
        nmap_object[key].pop('state')
        nmap_object[key].pop('macaddress')

        if is_valid_ip(key):
            # Flatten nmap reverse-lookups
            if len(nmap_object[key]['hostname']) > 0 and type(nmap_object[key]['hostname'][0]) is dict:
                nmap_object[key]['hostname'][0] = nmap_object[key]['hostname'][0]['name']
            if len(domains) > 0:
                # Append known domain to hostnames if present
                for domain_item in domains:
                    if key == domain_item['address']:
                        nmap_object[key]['hostname'].append(domain_item['hostname'])

            for port in nmap_object[key]['ports']:
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
    return nmap_object


def print_json(nmap_object):
    if args.pretty:
        json_object = json.dumps(nmap_object, indent=2)
    else:
        json_object = json.dumps(nmap_object)
    print(json_object)


def service_main():
    nmap_result = dict[Any, Any]
    first_run = True

    while True:
        if first_run:
            nmap_result = main()
            print_json(nmap_result)
        else:
            previous_nmap_result = nmap_result
            nmap_result = main()
            compare_dicts(previous_nmap_result, nmap_result)

        # Sleep for a bit or we will hog CPUs
        time.sleep(os.environ.get('KIRO_INTERVAL', 30))
        first_run = False


def main():
    # Collect target_ips
    target_ips, domains = collect_targets(targets)

    # Run nmap portscan
    nmap_result: dict[Any, Any] = portscan(target_ips)

    # Remove unwanted nmap data from object
    nmap_result = cleanup_nmap_object(nmap_result, domains)
    nmap_result['flags'] = []
    nmap_result = run_domain_checks(nmap_result, domains)
    nmap_result = run_port_checks(nmap_result, domains)

    return nmap_result


# Handle cli arguments
parser = argparse.ArgumentParser(description='Scan networks + domains to assess and improve security posture.')
parser.add_argument("-D", "--daemon", action='store_true', help='Run as service')
parser.add_argument("-H", "--hosts", help="List of hosts separated by commas", type=str)
parser.add_argument("-c", "--compare", action='store_true', help='Compare output to previous file')
parser.add_argument("-f", "--file", action='store_true', help='Write json output to file')
parser.add_argument("-p", "--pretty", action='store_true', help='Prettier output')
parser.add_argument("-wl", "--wordlist", help='Specify wordlist-file with subdomains', type=str)

args = parser.parse_args()

# Get current datetime
current_date_time = time.strftime("%Y%m%d-%H%M%S")


# Use host argument as target if present else use predefined
if args.hosts:
    targets = args.hosts.split(',')
else:
    try:
        targets = os.environ['KIRO_TARGETS'].split(',')  # Swap this to getenv
    except KeyError:
        # No targets specified, exit with error
        print('No targets specified', file=sys.stderr)
        exit(1)


# Check if we're running this as a service, loop if true
if args.daemon or os.environ.get('KIRO_DAEMON', 'false').lower() == 'true':
    service_main()
else:
    nmap_result_single_run = main()
    print_json(nmap_result_single_run)


if args.file:
    with open("netmon_" + current_date_time + ".txt", 'w') as fp:
        fp.write(nmap_json)


if args.compare:
    # Complete result is stored into a file. It's time to find
    # and load previous file result to compare with current.
    compare_files_as_json()
