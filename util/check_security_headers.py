import re
from typing import Tuple


EVAL_WARN = 0
EVAL_OK = 1


def eval_x_frame_options(contents: str) -> Tuple[int, list]:
    if contents.lower() in ['deny', 'sameorigin']:
        return EVAL_OK, []

    return EVAL_WARN, []


def eval_content_type_options(contents: str) -> Tuple[int, list]:
    if contents.lower() == 'nosniff':
        return EVAL_OK, []

    return EVAL_WARN, []


def eval_x_xss_protection(contents: str) -> Tuple[int, list]:
    # This header is deprecated but still used quite alot
    #
    # value '1' is dangerous because it can be used to block legit site features. If this header is defined, either
    # one of the below values if recommended
    if contents.lower() in ['1; mode=block', '0']:
        return EVAL_OK, []

    return EVAL_WARN, []


def eval_sts(contents: str) -> Tuple[int, list]:
    if re.match("^max-age=[0-9]+\\s*(;|$)\\s*", contents.lower()):
        return EVAL_OK, []

    return EVAL_WARN, []


def eval_csp(contents: str) -> Tuple[int, list]:
    unsafe_rules = {
        "script-src": ["*", "'unsafe-eval'", "data:", "'unsafe-inline'"],
        "frame-ancestors": ["*"],
        "form-action": ["*"],
        "object-src": ["*"],
    }

    # There are no universal rules for "safe" and "unsafe" CSP directives, but we apply some common sense here to
    # catch some obvious lacks or poor configuration
    csp_unsafe = False
    csp_notes = []

    csp_parsed = csp_parser(contents)

    for rule in unsafe_rules:
        if rule not in csp_parsed:
            if '-src' in rule and 'default-src' in csp_parsed:
                # fallback to default-src
                for unsafe_src in unsafe_rules[rule]:
                    if unsafe_src in csp_parsed['default-src']:
                        csp_unsafe = True
                        csp_notes.append(
                            "Directive {} not defined, and default-src contains unsafe source {}".format(
                                rule, unsafe_src))
            elif 'default-src' not in csp_parsed:
                csp_notes.append(
                    "No directive {} nor default-src defined in the Content Security Policy".format(rule))
                csp_unsafe = True
        else:
            for unsafe_src in unsafe_rules[rule]:
                if unsafe_src in csp_parsed[rule]:
                    csp_notes.append("Unsafe source {} in directive {}".format(unsafe_src, rule))
                    csp_unsafe = True

    if csp_unsafe:
        return EVAL_WARN, csp_notes

    return EVAL_OK, []


def eval_version_info(contents: str) -> Tuple[int, list]:
    # Poor guess whether the header value contain something that could be a server banner including version number
    if len(contents) > 3 and re.match(".*[^0-9]+.*\\d.*", contents):
        return EVAL_WARN, []

    return EVAL_OK, []


def eval_permissions_policy(contents: str) -> Tuple[int, list]:
    # Configuring Permission-Policy is very case-specific, and it's difficult to define a particular recommendation.
    # We apply here a logic, that access to privacy-sensitive features and payments API should be restricted.

    pp_parsed = permissions_policy_parser(contents)
    notes = []
    pp_unsafe = False
    restricted_privacy_policy_features = ['camera', 'geolocation', 'microphone', 'payment']

    for feature in restricted_privacy_policy_features:
        if feature not in pp_parsed or '*' in pp_parsed.get(feature):
            pp_unsafe = True
            notes.append("Privacy-sensitive feature '{}' is not restricted to specific origins.".format(feature))

    if pp_unsafe:
        return EVAL_WARN, notes

    return EVAL_OK, []


def eval_referrer_policy(contents: str) -> Tuple[int, list]:
    if contents.lower().strip() in [
        'no-referrer',
        'no-referrer-when-downgrade',
        'origin',
        'origin-when-cross-origin',
        'same-origin',
        'strict-origin',
        'strict-origin-when-cross-origin',
    ]:
        return EVAL_OK, []

    return EVAL_WARN, ["Unsafe contents: {}".format(contents)]


def csp_parser(contents: str) -> dict:
    csp = {}
    directives = contents.split(";")
    for directive in directives:
        directive = directive.strip().split()
        if directive:
            csp[directive[0]] = directive[1:] if len(directive) > 1 else []

    return csp


def permissions_policy_parser(contents: str) -> dict:
    policies = contents.split(",")
    retval = {}
    for policy in policies:
        match = re.match('^(\\w*)=(\\(([^)]*)\\)|\\*|self)$', policy)
        if match:
            feature = match.groups()[0]
            feature_policy = match.groups()[2] if match.groups()[2] is not None else match.groups()[1]
            retval[feature] = feature_policy.split()

    return retval


class SecurityHeadersException(Exception):
    pass


class SecurityHeaders:

    SECURITY_HEADERS_DICT = {
        'x-frame-options': {
            'recommended': True,
            'eval_func': eval_x_frame_options,
        },
        'strict-transport-security': {
            'recommended': True,
            'eval_func': eval_sts,
        },
        'content-security-policy': {
            'recommended': True,
            'eval_func': eval_csp,
        },
        'x-content-type-options': {
            'recommended': True,
            'eval_func': eval_content_type_options,
        },
        'x-xss-protection': {
            # X-XSS-Protection is deprecated; not supported anymore, and may be even dangerous in older browsers
            'recommended': False,
            'eval_func': eval_x_xss_protection,
        },
        'referrer-policy': {
            'recommended': True,
            'eval_func': eval_referrer_policy,
        },
        'permissions-policy': {
            'recommended': True,
            'eval_func': eval_permissions_policy,
        }
    }

    SERVER_VERSION_HEADERS = [
        'x-powered-by',
        'server',
        'x-aspnetmvc-version',
        'x-generator',
        'x-dupral-cache'
        'x-server',
        'x-aspnet-version',
        'x-wix-renderer-server'
    ]

    def __analyze(self):
        """ Default return array """
        retval = {}

        if not self.headers:
            raise SecurityHeadersException("Headers not found")

        """ Loop through headers and evaluate the risk """
        for header in self.SECURITY_HEADERS_DICT:
            if header in self.headers:
                eval_func = self.SECURITY_HEADERS_DICT[header].get('eval_func')
                if not eval_func:
                    raise SecurityHeadersException("No evaluation function found for header: {}".format(header))
                res, notes = eval_func(self.headers[header])
                retval[header] = {
                    'defined': True,
                    'warn': res == EVAL_WARN,
                    'contents': self.headers[header],
                    'notes': notes,
                }

            else:
                warn = self.SECURITY_HEADERS_DICT[header].get('recommended')
                retval[header] = {'defined': False, 'warn': warn, 'contents': None, 'notes': []}

        for header in self.SERVER_VERSION_HEADERS:
            if header in self.headers:
                res, notes = eval_version_info(self.headers[header])
                retval[header] = {
                    'defined': True,
                    'warn': res == EVAL_WARN,
                    'contents': self.headers[header],
                    'notes': notes,
                }

        return retval

    def __init__(self, headers):
        self.headers = {key.lower(): val.lower() for key, val in headers.items()}

    @staticmethod
    def analyze(headers) -> list:
        findings = []
        sh = SecurityHeaders(headers)
        result = sh.__analyze()

        if not result:
            return findings

        for header, value in result.items():
            if value['warn']:
                notes = []

                if not value['defined']:
                    message = "missing"
                else:
                    message = value['contents']
                    notes = value['notes']

                finding = {
                    header: message
                }
                if notes:
                    finding.update({"notes": notes})

                findings.append(finding)

        return findings
