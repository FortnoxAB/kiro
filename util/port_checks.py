from util.ports.get_min_tls import get_lowest_tls_version
from util.ports.check_if_http import check_http
from util.ports.get_http_header import get_http_header, get_all_http_headers
from util.is_valid_ip import is_valid_ip


def run_port_checks(nmap_object, domains):
    for ip, item in nmap_object.items():
        if is_valid_ip(ip):
            for port in nmap_object[ip]['ports']:
                # if there is TLS, make sure it only accept TLS1.2 or newer.
                for domain in nmap_object[ip]['hostname']:
                    if port.get('service').get('tunnel') == 'ssl':
                        min_tls = get_lowest_tls_version(ip, domain, port['portid'])
                        if min_tls != 'TLSv1.2' and min_tls != 'Unsupported TLS':
                            nmap_object['flags'].append(
                                {"port": port['portid'], "domain": domain, "ip": ip, "msg": min_tls, "type": "port"})

                    # Run HTTP based checks if HTTP is present on port
                    proto = check_http(ip, domain, port['portid'])
                    if proto != 'Neither':
                        # Get http response headers
                        httpheaders, http_status_code = get_all_http_headers(ip, domain, port['portid'], proto)
                        # Check for CSP among the response headers.
                        # if type(httpheaders) == dict and httpheaders != {} and 'Content-Security-Policy' not in httpheaders:
                        #    nmapdata['flags'].append({"port": port['portid'],"domain": domain, "ip": ip, "msg": "No Content-Security-Policy present","type":"port"})
    return nmap_object
