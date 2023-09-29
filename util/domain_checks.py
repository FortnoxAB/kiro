from util.domains.axfr import is_domain_available_for_axfr
from util.domains.dnssec import is_dnssec_enabled
from util.domaintype import is_subdomain

# Iterate through all domains present in nmapdata, run checks and add feed results back to nmapdata
def run_domain_checks(nmapdata, domains):
    # Create a list that will hold unique domains
    deduplicated_domains = set()
    # Add domains to unique list
    for domain_item in domains:
        deduplicated_domains.add(domain_item['hostname'])
    # Iterate deduplicated list of domains and run tests
    for domain in deduplicated_domains:
        if is_subdomain(domain) == False:
            # Check if domain transfer is available
            if is_domain_available_for_axfr(domain):
                nmapdata['flags'].append({"domain": domain, "msg": domain + " is available for transfer.", "url": 'https://www.cisa.gov/news-events/alerts/2015/04/13/dns-zone-transfer-axfr-requests-may-leak-domain-information', "type":"domain"})
            if is_dnssec_enabled(domain) == False:
                nmapdata['flags'].append({"domain": domain, "msg": domain + " doesn't have DNSSEC enabled","type":"domain"})
    return nmapdata