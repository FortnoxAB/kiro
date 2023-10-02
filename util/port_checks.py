from util.ports.get_min_tls import get_lowest_tls_version
from util.ports.check_if_http import check_http
from util.ports.get_http_header import get_http_header,get_all_http_headers
from util.is_valid_ip import is_valid_ip

def run_port_checks(nmapdata, domains):
    for ip, item in nmapdata.items():
        if is_valid_ip(ip):
            for port in nmapdata[ip]['ports']:
                # if there is TLS, make sure it only accept TLS1.2 or newer.
                for domain in nmapdata[ip]['hostname']:
                    if port.get('service').get('tunnel') == 'ssl':
                        mintls = get_lowest_tls_version(ip,domain,port['portid'])
                        if mintls != 'TLSv1.2' and mintls != 'Unsupported TLS':
                            nmapdata['flags'].append({"port": port['portid'],"domain": domain, "ip": ip, "msg": mintls,"type":"port"})

                    # Run HTTP based checks if HTTP is present on port
                    proto = check_http(ip,domain, port['portid'])
                    if proto != 'Neither':
                        # Get http response headers
                        httpheaders, http_status_code = get_all_http_headers(ip,domain,port['portid'],proto)
                        # Check for CSP among the response headers.
                        #if type(httpheaders) == dict and httpheaders != {} and 'Content-Security-Policy' not in httpheaders:
                        #    nmapdata['flags'].append({"port": port['portid'],"domain": domain, "ip": ip, "msg": "No Content-Security-Policy present","type":"port"})
    return nmapdata
