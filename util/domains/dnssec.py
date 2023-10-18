import dns.resolver


def is_dnssec_enabled(domain):
    try:
        # Create a DNS resolver
        resolver = dns.resolver.Resolver(configure=False)

        # Make sure we use cloudflare as local DNS might not have DNSSEC support
        resolver.nameservers = ['1.1.1.1']

        # Query the DS (Delegation Signer) records for the domain
        ds_records = resolver.query(domain, dns.rdatatype.DS)

        # If DS records are found, DNSSEC is enabled
        if ds_records:
            return True
        else:
            return False
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        # Raised when the domain doesn't exist or has no DNS records
        return False
    except dns.exception.DNSException:
        # Raised for any other DNS-related exceptions
        return False
