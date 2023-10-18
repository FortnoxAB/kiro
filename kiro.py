from typing import Any

from util.portscan import *
from util.compare import compare_files_as_json, compare_dicts
from util.dns_enum import dns_enum
from util.domain_checks import run_domain_checks
from util.port_checks import run_port_checks
from util.domaintype import is_subdomain
from util.is_valid_ip import is_valid_ip
from util.directory_brute_force import BruteForce

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


def brute_force_directories(nmap_object):
    for ip, item in nmap_object.items():
        if is_valid_ip(ip):
            host_name_to_use = ip

            try:
                # Check if any valid hostnames exists, start with hostnames that include main domain.
                for host_name in item["hostname"]:
                    for target in targets:
                        if target in host_name:
                            host_name_to_use = host_name

                for port in item["ports"]:
                    if port['service'] and port['service']['name']:
                        try:
                            service_name = port['service']['name']
                            if service_name == "https" or service_name == "http":
                                port_number = ""
                                if port["portid"] != "80" and port["portid"] != "443":
                                    port_number = ":" + port["portid"]
                                url = service_name + "://" + host_name_to_use + port_number
                                brute_result = BruteForce.start(url, 3)
                                port["brut"] = brute_result
                        except Exception as e:
                            print("PORT exception: " + str(e))
                            if port and not port["brut"]:
                                port["brut"] = ["Test failed"]
            except Exception as e:
                print("outer exception: " + str(e))
                continue


def service_main():
    nmap_result = dict[Any, Any]
    first_run = True

    while True:
        if first_run:
            nmap_result = main(False)
            print_json(nmap_result)
        else:
            previous_nmap_result = nmap_result
            nmap_result = main(False)
            compare_dicts(previous_nmap_result, nmap_result)

        # Sleep for a bit or we will hog CPUs
        time.sleep(os.environ.get('KIRO_INTERVAL', 30))
        first_run = False


def main(perform_brute: bool):
    # Collect target_ips
    target_ips, domains = collect_targets(targets)

    # Run nmap portscan
    nmap_result: dict[Any, Any] = portscan(target_ips)

    # Remove unwanted nmap data from object
    nmap_result = cleanup_nmap_object(nmap_result, domains)
    nmap_result['flags'] = []
    nmap_result = run_domain_checks(nmap_result, domains)
    nmap_result = run_port_checks(nmap_result, domains)

    # Brute force directories and files
    if perform_brute:
        brute_force_directories(nmap_result)

    return nmap_result


# Handle cli arguments
parser = argparse.ArgumentParser(description='Scan networks + domains to assess and improve security posture.')
parser.add_argument("-D", "--daemon", action='store_true', help='Run as service')
parser.add_argument("-H", "--hosts", help="List of hosts separated by commas", type=str)
parser.add_argument("-c", "--compare", action='store_true', help='Compare output to previous file')
parser.add_argument("-f", "--file", action='store_true', help='Write json output to file')
parser.add_argument("-p", "--pretty", action='store_true', help='Prettier output')
parser.add_argument("-b", "--brute",
                    action='store_true',
                    help='Brute force directories and files for web facing ports (cmd only)')
parser.add_argument("-wl", "--wordlist", help='Specify wordlist file with subdomains', type=str)

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
    brute = True if args.brute else False
    nmap_result_single_run = main(brute)
    print_json(nmap_result_single_run)


if args.file:
    with open("netmon_" + current_date_time + ".txt", 'w') as fp:
        fp.write(nmap_json)


if args.compare:
    # Complete result is stored into a file. It's time to find
    # and load previous file result to compare with current.
    compare_files_as_json()
