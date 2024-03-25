import requests


class Cors:
    __test_cases = ["null",
                    "{protocol}://any-domain-to-use-for-origin.com",
                    "{protocol}://{target}_any-domain-to-use-for-origin.com",
                    "{protocol}://{target}.any-domain-to-use-for-origin.com",
                    "{protocol}://{target}any-domain-to-use-for-origin.com",
                    "{protocol}://subdomain.{target}",
                    "{protocol}://{target.}",
                    "{protocol}://{target-}"]

    def __analyze(self) -> dict:
        origins = [self.target_url]
        for test_case in self.__test_cases:
            if "{protocol}" in test_case:
                test_case = test_case.replace("{protocol}", self.http_protocol)

            if "{target-}" in test_case:
                origins.append(test_case.replace("{target-}", self.target[:-1]))
            elif "{target.}" in test_case:
                origins.append(test_case.replace("{target.}", self.target.replace('.', 'x', 1)))
            elif "{target}" in test_case:
                origins.append(test_case.replace("{target}", self.target))
            else:
                origins.append(test_case)

        result = {}
        for origin in origins:
            headers = {"Origin": origin}
            response = requests.get(self.target_url, headers=headers, allow_redirects=True, verify=False)
            response_headers = {key.lower(): val.lower() for key, val in response.headers.items()}

            if "access-control-allow-origin" in response_headers:
                if response_headers["access-control-allow-origin"].lower() == "*":
                    result.update({"access-control-allow-origin: *": "Wildcard in origin for CORS header"})
                if origin in response_headers["access-control-allow-origin"]:
                    result.update({"access-control-allow-origin: <reflected>": "Origin is reflected for CORS header"})
            if "access-control-allow-credentials" in response_headers:
                if response_headers["access-control-allow-credentials"].lower() == "true":
                    result.update({"access-control-allow-credentials: true": "Credentials for CORS header"})

        return result

    def __init__(self, target, target_url, http_protocol):
        self.target = target
        self.target_url = target_url
        self.http_protocol = http_protocol

    @staticmethod
    def analyze(domain, port, http_protocol) -> list:
        findings = []

        try:
            target_url = f"{http_protocol.lower()}://{domain}:{port}"
            target = f"{domain}:{port}"

            check_cors = Cors(target, target_url, http_protocol)
            result = check_cors.__analyze()

            for key, val in result.items():
                findings.append({key: val})
        except Exception as e:
            print("Analyze CORS exception: " + str(e))

        return findings
