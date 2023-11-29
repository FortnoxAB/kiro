from util.domains.axfr import is_domain_available_for_axfr
from util.domains.dnssec import is_dnssec_enabled
from util.domaintype import is_subdomain


# Iterate through all domains present in nmap_data, run checks and add feed results back to nmap_data
def run_domain_checks(nmap_object, domains):
    # Create a list that will hold unique domains
    deduplicated_domains = set()

    # Add domains to unique list
    for domain_item in domains:
        deduplicated_domains.add(domain_item['hostname'])

    # Iterate deduplicated list of domains and run tests
    for domain in deduplicated_domains:
        if not is_subdomain(domain):
            # Check if domain transfer is available
            if is_domain_available_for_axfr(domain):
                nmap_object['flags'].append({"domain": domain, "msg": domain + " is available for transfer.",
                                             "url": 'https://www.cisa.gov/news-events/alerts/2015/04/13/dns-zone-transfer-axfr-requests-may-leak-domain-information',
                                             "type": "domain"})
            if not is_dnssec_enabled(domain):
                nmap_object['flags'].append(
                    {"domain": domain, "msg": domain + " doesn't have DNSSEC enabled", "type": "domain"})

    return nmap_object
