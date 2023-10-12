# Kiro
Scan your networks/domains to assess and improve your security posture.

## Setup
Make sure you have docker available or python setup with nmap from your packagedistributer

```
pip3 install -r requirements.txt
```
## Environment

>KIRO_DAEMON, set to true if you wish kiro as a daemon.  
KIRO_TARGET, List of hosts, CIDRs and domains separated by commas  
KIRO_INTERVAL, Add interval (in seconds) between runs when run as daemon.  

## Usage

```
usage: kiro.py [-h] [-D] [-H HOSTS] [-c] [-f] [-p] [-wl WORDLIST]

Scan networks + domains to assess and improve security posture.

options:
  -h, --help            show this help message and exit
  -D, --daemon          Run as service
  -H HOSTS, --hosts HOSTS
                        List of hosts separated by commas
  -c, --compare         Compare output to previous file
  -f, --file            Write json output to file
  -p, --pretty          Prettier output
  -wl WORDLIST, --wordlist WORDLIST
                        Specify wordlist-file with subdomains
```
Examples:
```
python3 kiro.py -H security.guru,10.0.0.0/8 --pretty
docker run -e KIRO_TARGETS=security.guru,10.0.0.0/8 quay.io/fortnox/kiro:0.1
```

## Todo

* Prettier output
* Slack notifications
* More detections

## Author

Written by the infosec team at Fortnox (https://www.fortnox.se)
