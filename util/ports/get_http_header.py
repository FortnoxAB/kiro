import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def get_http_header(ip, hostheader, port, responseheader):
    url = f"http://{ip}:{port}"
    headers = {'Host': hostheader}

    try:
        response = requests.get(url, headers=headers,allow_redirects=False)
        
        if response.status_code == 200:
            if responseheader in response.headers:
                return True
            else:
                return False, f"Response header '{responseheader}' not found in the response headers."
        else:
            return False, f"HTTP request failed with status code {response.status_code}."
    except requests.exceptions.RequestException as e:
        return False, f"An error occurred: {e}"

def get_all_http_headers(ip, hostheader,port,proto):
   
    url = f"{proto.lower()}://{ip}:{port}"
    headers = {'Host': hostheader}

    try:
        response = requests.get(url, headers=headers,allow_redirects=False,verify=False)
        
        return response.headers, response.status_code
    except requests.exceptions.RequestException as e:
        return False, f"An error occurred: {e}"