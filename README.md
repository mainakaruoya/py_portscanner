### Port Scanner (Basic)
A simple, command-line port scanner for Python. Can carry out a TCP SYN and UDP ping scan, or both, depending on the flags that have been set.
Requires the use of Scapy, which is in the requirements.txt file, and can be installed thus:

`pip install -r requirements.txt`

#### Usage and Options
Convention for the usage below -- curly brackets indicate mandatory arguments; square brackets indicate optional arguments.
Use `python3` instead of `python` if working from Linux.

Usage:
`python portscanner.py [-h] -a <IP address/range> -p <port number/range> {-t | -u | -b}`

Options:

`-h, --help            show this help message and exit`

`-a <IP address/range>, --address <IP address/range>`

`-p <port number/range>, --port <port number/range>`

`-t, --tcp             Carry out a TCP SYN Scan for the given port/range of ports`

`-u, --udp             Carry out a UDP Ping Scan for the given port/range of ports`

`-b, --both            Carry out both a TCP SYN and UDP Ping Scan`

The sections below detail some links to visit that can help one in developing a port scanner.

#### Using Argparse
https://www.cherryservers.com/blog/how-to-use-python-argparse
https://docs.python.org/3/howto/argparse.html
https://www.geeksforgeeks.org/command-line-option-and-argument-parsing-using-argparse-in-python/
https://www.digitalocean.com/community/tutorials/how-to-use-argparse-to-write-command-line-programs-in-python

#### Working with IP addresses
The IP address type in Python: https://docs.python.org/3/howto/ipaddress.html#ipaddress-howto

Extra links:
https://www.geeksforgeeks.org/how-to-manipulate-ip-addresses-in-python-using-ipaddress-module/
https://www.geeksforgeeks.org/working-with-ip-addresses-in-python/

#### Using Scapy
UDP Ping Scan: https://scapy.readthedocs.io/en/latest/usage.html#udp-ping

TCP SYN Scan: https://scapy.readthedocs.io/en/latest/usage.html#syn-scans

#### Other Useful Content
To create the UDP Port Scan, I referenced the following code, specifically the udp_scan function:
[Source code](https://github.com/cptpugwash/Scapy-port-scanner/blob/master/port_scanner.py)

Colorama to color output text: https://stackoverflow.com/questions/287871/how-do-i-print-colored-text-to-the-terminal

Another link on Colorama usage: https://www.codeease.net/programming/python/how-to-bold-in-colorama

#### Suppressing Scapy Messages
Cf. the following source: https://stackoverflow.com/questions/13249341/suppress-scapy-warning-message-when-importing-the-module