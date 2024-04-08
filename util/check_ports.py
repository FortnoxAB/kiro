from util.ports.get_min_tls import get_lowest_tls_version
from util.ports.check_if_http import check_http
from util.ports.get_http_header import get_all_http_headers
from util.is_valid_ip import is_valid_ip
from util.check_security_headers import SecurityHeaders
from util.check_cookie_flags import CookieFlags
from util.check_cors import Cors


def run_port_checks(nmap_object, verbose=False):
    """
    Perform mandatory checks / validations for each port.
    Checks implemented are
    (1) Minimum TLS version
    (2) Security headers
    (3) Cookie flags
    (4) CORS misconfigurations
    """

    for ip, item in nmap_object.items():
        if is_valid_ip(ip):
            if verbose:
                print(f"Port Checks for ip {ip}")

            for port in nmap_object[ip]['ports']:
                for domain in nmap_object[ip]['hostname']:
                    http_protocol = port.get('service').get('name')
                    port_id = port['portid']

                    if port.get('service').get('tunnel') == 'ssl':
                        min_tls = get_lowest_tls_version(ip, domain, port_id)
                        if min_tls != 'TLSv1.2' and min_tls != 'Unsupported TLS':
                            nmap_object['flags'].append(
                                {"port": port_id, "domain": domain, "ip": ip, "msg": min_tls, "type": "port"})

                    # Run HTTP based checks if HTTP is present on port
                    proto = check_http(ip, domain, port_id)

                    if verbose:
                        print(f"-- {domain}: {port_id}")

                    if proto:
                        http_headers, http_cookies = (
                            get_all_http_headers(ip, domain, port_id, http_protocol, verbose))

                        if http_headers:
                            security_headers = SecurityHeaders.analyze(http_headers, verbose)
                            if security_headers:
                                port.update({"security_headers": security_headers})

                        if http_cookies or http_headers:
                            cookie_flags = CookieFlags.analyze(http_headers, http_cookies, verbose)
                            if cookie_flags:
                                port.update({"cookie_flags": cookie_flags})

                        cors = Cors.analyze(domain, port_id, http_protocol, verbose)
                        if cors:
                            port.update({"cors": cors})

    return nmap_object
