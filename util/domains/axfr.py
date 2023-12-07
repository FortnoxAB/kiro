import dns.query
import dns.zone
import dns.resolver  # Import the resolver module to query NS records
import socket
from util.domaintype import is_subdomain


def get_nameservers(domain_name):
    try:
        # Query the NS records for the domain
        ns_records = dns.resolver.resolve(domain_name, 'NS')

        # Extract and return the nameserver addresses
        nameservers = [str(ns.target) for ns in ns_records]
        return nameservers
    except dns.exception.DNSException:
        # Return an empty list if NS records cannot be retrieved
        return []


def is_domain_available_for_axfr(domain_name):
    """ Check if domain transfer is available for domain """

    try:
        # Get the nameservers for the domain
        nameservers = get_nameservers(domain_name)

        if not nameservers:
            # No nameservers found, so domain is not available for AXFR
            return False

        for nameserver in nameservers:
            try:
                nameserver_ips = socket.gethostbyname_ex(nameserver)[2]
                # Create a DNS zone object for the domain using each nameserver
                for nameserver_ip in nameserver_ips:
                    zone = dns.zone.from_xfr(dns.query.xfr(nameserver_ip, domain_name))
                    # If the zone transfer was successful, the domain is available for AXFR
                    return True
            except (dns.exception.FormError, ConnectionResetError):
                continue  # Move to the next nameserver if this one failed

        # If all nameservers failed, the domain is not available for AXFR
        return False
    except dns.exception.DNSException:
        # If there's an issue querying nameservers, consider the domain not available
        return False
