from typing import Any

from util.portscan import *
from util.compare import compare_files_as_json, compare_dicts
from util.dns_enum import dns_enum
from util.check_domain import run_domain_checks
from util.check_ports import run_port_checks
from util.domaintype import is_subdomain
from util.is_valid_ip import is_valid_ip
from util.directory_brute_force import BruteForce

import json
import time
import datetime
import argparse
import socket
import os


def collect_target_ip_addresses(target_list):
    """ Collect target ip addresses, including for all found subdomains """

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


def nmap_scan_summary(nmap_object, start):
    """ Collect scan summary: start, finished, summary and elapsed time """

    runtime = nmap_object.get("runtime", {})
    return {
        "start": str(start),
        "finished": str(datetime.datetime.now()),
        "summary": runtime.get("summary"),
        "elapsed": runtime.get("elapsed"),
        "exit": runtime.get("exit")
    }


def cleanup_nmap_object(nmap_object, domains):
    """ Remove unwanted nmap data from object for readability """

    if 'runtime' in nmap_object:
        nmap_object.pop('runtime')
    if 'stats' in nmap_object:
        nmap_object.pop('stats')
    if 'task_results' in nmap_object:
        nmap_object.pop('task_results')

    for key in nmap_object.keys():
        if 'osmatch' in nmap_object[key]:
            nmap_object[key].pop('osmatch')
        if 'state' in nmap_object[key]:
            nmap_object[key].pop('state')
        if 'macaddress' in nmap_object[key]:
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
                if 'state' in port:
                    port.pop('state')
                if 'reason' in port:
                    port.pop('reason')
                if 'reason_ttl' in port:
                    port.pop('reason_ttl')
                if 'cpe' in port:
                    port.pop('cpe')
                if 'method' in port['service']:
                    port['service'].pop('method')
                if 'conf' in port['service']:
                    port['service'].pop('conf')
                try:
                    if 'servicefp' in port['service']:
                        port['service'].pop('servicefp')
                except:
                    continue
    return nmap_object


def cleanup_object(nmap_object):
    """ Remove additional nmap data that might exist in the general "flags" section """

    for key in nmap_object.keys():
        if is_valid_ip(key):
            for port in nmap_object[key]['ports']:
                if 'scripts' in port:
                    port.pop('scripts')
                if 'security_headers' in port:
                    port.pop('security_headers')
                if 'cookie_flags' in port:
                    port.pop('cookie_flags')
                if 'cors' in port:
                    port.pop('cors')
    return nmap_object


def get_vulnerabilities(nmap_object) -> list:
    """
    For each vulnerability registered in nmap data object,
    summarize the information wanted and group over
    IP address and port.
    """

    vulnerabilities = []

    for current_ip, current_values in nmap_object.items():
        if not is_valid_ip(current_ip):
            continue

        current_hostname = current_values.get("hostname")

        for current_port in current_values.get("ports", []):
            portid = current_port.get("portid")
            scripts = current_port.get("scripts")
            security_headers = current_port.get("security_headers")
            cookie_flags = current_port.get("cookie_flags")
            cors = current_port.get("cors")

            if scripts or security_headers or cookie_flags or cors:
                item_vulnerabilities = []

                findings = {
                    "hostname": current_hostname,
                    "ip": current_ip,
                    "port": portid,
                    "items": []
                }

                if scripts:
                    script_items = []
                    for item in scripts:
                        if "name" in item:
                            if item['name'] == "fingerprint-strings":
                                continue
                        if 'raw' in item:
                            item.pop("raw")
                        script_items.append(item)

                    item_vulnerabilities.append({
                        "nmap_vulners": script_items
                    })

                if security_headers:
                    security_header_items = []
                    for item in security_headers:
                        security_header_items.append(item)

                    item_vulnerabilities.append({
                        "security_headers": security_header_items
                    })

                if cookie_flags:
                    cookie_flag_items = []
                    for item in cookie_flags:
                        cookie_flag_items.append(item)

                    item_vulnerabilities.append({
                        "cookie_flags": cookie_flag_items
                    })

                if cors:
                    cors_items = []
                    for item in cors:
                        cors_items.append(item)

                    item_vulnerabilities.append({
                        "cors": cors_items
                    })

                findings["items"] = item_vulnerabilities
                vulnerabilities.append(findings)

    return vulnerabilities


def print_json(nmap_object, default_text_if_empty=None):
    if nmap_object:
        if args.pretty:
            json_object = json.dumps(nmap_object, indent=2)
        else:
            json_object = json.dumps(nmap_object)
            json_object = " ".join(json_object.splitlines())
        print(json_object)
    else:
        if default_text_if_empty:
            print(default_text_if_empty)


def verbose(title, message):
    if args.verbose:
        if isinstance(message, str):
            print(f"{title}: {message}")
        elif isinstance(message, list):
            print(f"{title}")
            for item in message:
                if isinstance(item, str):
                    print(f"-- {item}")
                elif isinstance(item, dict):
                    for item2 in item.keys():
                        if isinstance(item2, str) and (item2 == "hostname" or item2 == "address"):
                            print(f"-- {item[item2]}")
                        else:
                            print(f"-- {item2}")


def brute_force_directories(nmap_object):
    """ Brute force directories and files (not available for service) """

    brute_dir = args.brutedir
    brute_php = args.brutephp

    for ip, item in nmap_object.items():
        if is_valid_ip(ip):
            host_name_to_use = ip

            try:
                # Check if any valid hostnames exists, start with hostnames that include main domain.
                for host_name in item['hostname']:
                    for target in targets:
                        if target in host_name:
                            host_name_to_use = host_name

                exclude_ports = ['80', '443']
                accept_protocols = ['http', 'https']

                for port in item['ports']:
                    if port['service'] and port['service']['name']:
                        try:
                            service_name = port['service']['name']

                            if service_name in accept_protocols:
                                port_id = '' if port['portid'] in exclude_ports else ':' + port['portid']
                                url = service_name + "://" + host_name_to_use + port_id

                                brute_result = []
                                if brute_dir:
                                    brute_result += BruteForce.start(url, 5, "./bruteforce_dir_wordlist.txt")
                                if brute_php:
                                    brute_result += BruteForce.start(url, 5, "./bruteforce_php_wordlist.txt")

                                port['brut'] = brute_result
                        except Exception as e:
                            # print('Brute Force - PORT exception: ' + str(e))
                            if port and not port['brut']:
                                port['brut'] = ['Test failed']
            except Exception as e:
                # print('Brute Force - exception: ' + str(e))
                continue


def service_main():
    nmap_result = dict[Any, Any]
    first_run = True

    while True:
        if first_run:
            nmap_result = main(False)
            print_json(nmap_result, "First run empty, check your settings")
        else:
            previous_nmap_result = nmap_result
            nmap_result = main(False)
            compare_result = compare_dicts(previous_nmap_result, nmap_result)
            print_json(compare_result, )

        # Sleep for a bit or we will hog CPUs
        time.sleep(os.environ.get('KIRO_INTERVAL', 30))
        first_run = False


def main(perform_brute: bool):
    start_datetime = datetime.datetime.now()
    verbose("Start", str(start_datetime))

    # Get IP addresses, scan, summarize and cleanup
    target_ips, domains = collect_target_ip_addresses(targets)
    verbose("Found Target IPs", target_ips)
    verbose("Found Domains", domains)

    verbose("Port Scan", "Start")
    nmap_result: dict[Any, Any] = portscan(target_ips)
    verbose("Nmap Scan Summary", "Start")
    summary = nmap_scan_summary(nmap_result, start_datetime)
    verbose("Nmap Cleanup", "Start")
    nmap_result = cleanup_nmap_object(nmap_result, domains)

    # Analyze vulnerability results and add to general "flags" section.
    # Vulnerabilities are group over IP address and port.
    nmap_result['flags'] = []
    verbose("Run Domain Checks", "Start")
    nmap_result = run_domain_checks(nmap_result, domains)
    verbose("Run Port Checks", "Start")
    nmap_result = run_port_checks(nmap_result, args.verbose)

    verbose("Get Vulnerabilities", "Start")
    vulnerabilities = get_vulnerabilities(nmap_result)
    if vulnerabilities:
        for vulnerability in vulnerabilities:
            nmap_result['flags'].append(vulnerability)

    nmap_result = cleanup_object(nmap_result)

    if perform_brute:
        verbose("Brute Force Directories", "Start")
        brute_force_directories(nmap_result)

    # When performing large scans over multiple domains the importance
    # of logging the actual scan summary's metadata seams reasonable
    print_json("")
    print_json(summary)

    return nmap_result


# Handle cli arguments
parser = argparse.ArgumentParser(description='Scan networks + domains to assess and improve security posture.')
parser.add_argument("-D", "--daemon", action='store_true', help='Run as service')
parser.add_argument("-H", "--hosts", help="List of hosts separated by commas", type=str)
parser.add_argument("-c", "--compare", action='store_true', help='Compare output to previous file')
parser.add_argument("-f", "--file", action='store_true', help='Write json output to file')
parser.add_argument("-p", "--pretty", action='store_true', help='Prettier output')
parser.add_argument("-v", "--verbose", action='store_true', help='Verbose output')
parser.add_argument("-wl", "--wordlist", help='Specify wordlist file with subdomains', type=str)
parser.add_argument("--brutedir",
                    action='store_true',
                    help='Brute force common directories and files for web facing ports (not available for service)')
parser.add_argument("--brutephp",
                    action='store_true',
                    help='Brute force common php files for web facing ports (not available for service)')

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
    brute = True if (args.brutedir or args.brutephp) else False
    nmap_result_single_run = main(brute)
    print_json(nmap_result_single_run, "Single CLI is empty")


if args.file:
    with open("netmon_" + current_date_time + ".txt", 'w') as fp:
        fp.write(nmap_json)


if args.compare:
    # Complete result is stored into a file. It's time to find
    # and load previous file result to compare with current.
    compare_files_as_json()
