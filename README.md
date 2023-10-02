# Kiro
Scan your networks/domains to assess and improve your security posture.

## Setup
Make sure you have docker available or python setup with nmap from your packagedistributer

```
pip3 install -r requirements.txt
```

## Usage

```
usage: kiro.py [-h] [-D] [-H HOSTS] [-c] [-f]

options:
  -h, --help              Show this help message and exit
  -D, --daemon            Run as service
  -H HOSTS, --hosts HOSTS Set targets and override KIRO_TARGETS env.
                          List of hosts, CIDRs and domains separated by commas
  -c, --compare           Compare output to previous file
  -f, --file              Write json output to file
  -p, --pretty            
```
Examples:
```
python3 kiro.py -H security.guru,10.0.0.0/8 --pretty
docker run -e KIRO_TARGETS=security.guru,10.0.0.0/8 quay.io/fortnox/kiro:0.1
```

## Todo

Ensure that requirements.txt is up to date
Slack notifications
Prettier output
More detections

## Author

Written by the infosec team at Fortnox (https://www.fortnox.se)
