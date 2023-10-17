from tld import get_tld


def is_subdomain(domain):
    # Convert to url since tld requires it...
    domain_tld = get_tld('http://' + domain, as_object=True)
    if domain_tld.subdomain:
        return True
    else:
        return False
