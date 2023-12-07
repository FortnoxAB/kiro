class CookieFlags:
    def __analyze(self):
        retval = {}
        cookie_list = []

        # Loop through headers and evaluate the risk
        for key, val in self.headers.items():
            if key == "set-cookie":
                # If multiple cookies is set in set-cookie, split and process each
                counter = 0
                for cookie_name in self.cookies:
                    if str(cookie_name + "=") in val:
                        counter += 1

                if counter == 1:
                    # Only one cookie in "Set-Cookie" header
                    cookie_list.append(val)
                else:
                    # All cookies exist in "Set-Cookie" header
                    # Split string with cookie_name and loop result
                    cookie_index_list = []
                    for cookie_name2 in self.cookies:
                        cookie_index_list.append(val.index(str(cookie_name2 + "="), 0, len(val)))

                    cookie_index_list_ordered = sorted(cookie_index_list)
                    for i in range(len(cookie_index_list_ordered)):
                        pos = cookie_index_list_ordered[i]
                        pos_next = 0
                        if i < len(cookie_index_list_ordered) - 1:
                            pos_next = cookie_index_list_ordered[i+1]
                        else:
                            pos_next = len(val)
                        value = str(val[pos: pos_next])
                        value = value.rstrip(" ")
                        value = value.rstrip(",")
                        cookie_list.append(value)

        # Perform checks on each found cookie
        for cookie in cookie_list:
            cookie_name = cookie.split("=")[0]
            security_risks = []
            if "; httponly" not in cookie:
                security_risks.append("Missing HttpOnly")
            if "; secure" not in cookie:
                security_risks.append("Missing Secure")

            if security_risks:
                retval.update({cookie_name: ", ".join(security_risks)})

        return retval

    def __init__(self, headers, cookies):
        self.headers = {key.lower(): val.lower() for key, val in headers.items()}
        self.cookies = {key.lower(): val for key, val in cookies.items()}

    @staticmethod
    def analyze(headers, cookies) -> list:
        findings = []
        cookie_flags = CookieFlags(headers, cookies)
        result = cookie_flags.__analyze()

        if not result:
            return findings

        for key, val in result.items():
            findings.append({key: val})

        return findings
