from netaddr import IPNetwork, AddrFormatError


def is_valid_ip(address):
    try:
        IPNetwork(address)
        return True
    except (ValueError, AddrFormatError):
        return False
