import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def get_http_header(ip, host_header, port, response_header):
    url = f"http://{ip}:{port}"
    headers = {'Host': host_header}

    try:
        response = requests.get(url, headers=headers, allow_redirects=False)

        if response.status_code == 200:
            if response_header in response.headers:
                return True
            else:
                return False, f"Response header '{response_header}' not found in the response headers."
        else:
            return False, f"HTTP request failed with status code {response.status_code}."
    except requests.exceptions.RequestException as e:
        return False, f"An error occurred: {e}"


def get_all_http_headers(ip, host_header, port, proto):
    url = f"{proto.lower()}://{ip}:{port}"
    headers = {'Host': host_header}

    try:
        response = requests.get(url, headers=headers, allow_redirects=False, verify=False)

        headers = response.headers if response.headers else None
        cookies = response.cookies.get_dict() if response.cookies and response.cookies.get_dict() else None

        return headers, cookies
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return None, None
