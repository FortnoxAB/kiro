# Kiro
Scan your networks/domains to assess and improve your security posture.  
Brute force directories and files for web facing ports (not available when run as a service).  

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
usage: kiro.py [-h] [-D] [-H HOSTS] [-c] [-f] [-p] [--brutedir] [--brutephp] [-wl WORDLIST]

Scan networks + domains to assess and improve security posture.

options:
  -h, --help            Show this help message and exit
  -D, --daemon          Run as service
  -H HOSTS, --hosts HOSTS
                        List of hosts separated by commas
  -c, --compare         Compare output to previous file
  -f, --file            Write json output to file
  -p, --pretty          Prettier output
  -wl WORDLIST, --wordlist WORDLIST
                        Specify wordlist file with subdomains
  --brutedir            Brute force common directories and files for web facing ports (not available for service)
  --brutephp            Brute force common php files for web facing ports (not available for service)
```
Examples:
```
python3 kiro.py -H security.guru,10.0.0.0/8 --pretty
docker run -e KIRO_TARGETS=security.guru,10.0.0.0/8 quay.io/fortnox/kiro:0.1
```

## Output
The output is organized in sections:
```
{
    < Header >
}
{
    "IP1": { ... },
    "IP2": { ... },
    "IP3": { ... },
    "flags": []
}
```

Running below scan against a local python webserver exposing port 8000.
```
$ python3 kiro.py -p -H 127.0.0.1
```

### Header  
```
{
  "start": "2023-11-30 08:32:04.031768",
  "finished": "2023-11-30 08:32:11.400543",
  "summary": "Nmap done at Thu Nov 30 08:32:11 2023; 1 IP address (1 host up) scanned in 7.32 seconds",
  "elapsed": "7.32",
  "exit": "success"
}
```

### Per domain   
```
{
  "127.0.0.1": {
    "ports": [{
        "protocol": "tcp",
        "portid": "8000",
        "service": {
          "name": "http",
          "product": "SimpleHTTPServer",
          "version": "0.6",
          "extrainfo": "Python 3.10.12"
        }
    }],
    "hostname": ["localhost"]
  },
  < IP >: { ... },
  < IP >: { ... },
  ...
  < Flags >
}
```

### Flags (alerts)   
```
{
  < IP >: { ... },
  < IP >: { ... },
  ...
  "flags": [{
      "hostname": [
        "localhost"
      ],
      "ip": "127.0.0.1",
      "port": "8000",
      "items": [{
          "nmap_vulners": [{
              "name": "http-server-header",
              "data": { "0": "SimpleHTTP/0.6 Python/3.10.12" }
        }]
        },{
          "security_headers": [{
              "content-security-policy": "default-src 'self';script-src 'self' 'unsafe-inline';frame-ancestors 'none'",
              "notes": ["Unsafe source 'unsafe-inline' in directive script-src"]
            },{
              "x-frame-options": "missing"
            },{ 
              "x-xss-protection": "1"
            },{
              "permissions-policy": "missing"
            },{
              "server": "simplehttp/0.6 python/3.10.12"
          }]
        }
      ]
    }
  ]
```

## Todo

* Slack notifications
* More detections

## Author

Written by the infosec team at Fortnox (https://www.fortnox.se)
