from util.ports.get_min_tls import get_lowest_tls_version
from util.ports.check_if_http import check_http
from util.ports.get_http_header import get_all_http_headers
from util.is_valid_ip import is_valid_ip
from util.check_security_headers import SecurityHeaders
from util.check_cookie_flags import CookieFlags


def run_port_checks(nmap_object):
    """
    Perform mandatory checks / validations for each port.
    Checks implemented are
    (1) Minimum TLS version
    (2) Security headers
    (3) Cookie flags
    """

    for ip, item in nmap_object.items():
        if is_valid_ip(ip):
            for port in nmap_object[ip]['ports']:
                for domain in nmap_object[ip]['hostname']:
                    if port.get('service').get('tunnel') == 'ssl':
                        min_tls = get_lowest_tls_version(ip, domain, port['portid'])
                        if min_tls != 'TLSv1.2' and min_tls != 'Unsupported TLS':
                            nmap_object['flags'].append(
                                {"port": port['portid'], "domain": domain, "ip": ip, "msg": min_tls, "type": "port"})

                    # Run HTTP based checks if HTTP is present on port
                    proto = check_http(ip, domain, port['portid'])
                    if proto:
                        http_headers, http_cookies, http_status_code = (
                            get_all_http_headers(ip, domain, port['portid'], proto))

                        security_headers = SecurityHeaders.analyze(http_headers)
                        if security_headers:
                            port.update({"security_headers": security_headers})

                        cookie_flags = CookieFlags.analyze(http_headers, http_cookies)
                        if cookie_flags:
                            port.update({"cookie_flags": cookie_flags})

    return nmap_object
