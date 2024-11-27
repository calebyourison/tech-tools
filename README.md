# tech-tools: Basic Functions to Assess Hosts On a Network
---
`tech-tools` is geared towards the Low Voltage Security Industry, though its design is fairly general and could have other use cases.
The basic goal is to gather information about local hosts for potential troubleshooting.  Currently, only IPv4 is supported.

This projects makes use of the OS CLI and is currently supported on Linux and Windows.
For Linux, some features may not be included by default.  This project requires the presence of `traceroute` and `network-manager`.
Please refer to your distribution's documentation, though in many cases these packages can be installed using:
```bash
sudo apt-get install traceroute
sudo apt-get install network-manager
```

**Do not use `tech-tools` (or other networking tools) unless on your own network or on a network in which you have been given permission to operate.**

#### Getting Started
---

```bash
pip install tech-tools
```

Simple examination of local network with accompany DataFrame:
```bash
from tech_tools import local_devices

my_local_network_df = local_devices()
print(my_local_network_df)

Attempting to gather information for local devices, please wait...

            ip                mac      ports       company
0    10.10.0.1  54:AF:97:2D:14:30  [80, 443]        TPLink
1    10.10.0.4  58:B9:65:14:2D:6C        NaN         Apple
2    10.10.0.7  90:09:D0:22:41:DE  [80, 443]      Synology
```

By default, the function searches for the network associated with the machine's primary interface, and on ports [80, 443] but this behavior can be easily modified for different ports or for a network on a different valid interface.

```bash
my_local_network_df = local_devices(network='192.168.0.1/26', ports = [21, 22, 5000, 8000])
```

This function assumes a valid ping, which may not be the case for all hosts.  It also relies on the local arp table, though this table may not be fully populated for all devices.  Running the function multiple times may yield different results. 

An Alternative is to scan for hosts via TCP ports.

#### Basic TCP Scanning
---

Provide a list of IPv4 Addresses and a list of ports to the TCP scanner function.
List generating functions can aid in this process.  The scanner will return a DataFrame containing hosts along with a list of ports on which they responded.

```bash
from tech_tools import tcp_ip_port_scanner

from tech_tools.utilities import generate_range_from_subnet, generate_range_from_two_ips

subnet_to_scan = generate_range_from_subnet('10.10.0.1/20')
range_of_addresses_to_scan = generate_range_from_two_ips('10.10.0.1', '10.10.0.150')
manual_list_of_addresses_to_scan = ['10.10.0.1', '10.10.0.199', '10.10.0.201', ...]

ports_to_scan = [21, 22, 80, 443, 514]

results = tcp_ip_port_scanner(subnet_to_scan, ports_to_scan)

print(results)
               ip      ports
0       10.10.0.1  [80, 443]
1      10.10.0.19      [514]
2      10.10.0.26  [22, 514]
```
The preceding demonstrations assume that your machine has an address that matches the network on which it is probing.
Sometimes packet sniffing can be a helpful starting point when very little is known about the networking environment.  You could install `pyshark` or,
as is the direction of this project, use wireshark GUI to monitor activity for a short while and export packet dissections into JSON format. 

The following functions help to extract useful information from such a JSON file.

#### Wireshark JSON Analysis
---

Using the path to a valid file, produce a list of addresses that fall under the umbrella of private/local.
Alternatively, produce a DataFrame of sniffed Mac Addresses along with their associated manufacturing company.
Larger files will require more time to process, so use good judgement when capturing packets as a few hundred frames might provide enough information.  

```bash
from tech_tools.wireshark import wireshark_private_ips, wireshark_mac_addresses

path_to_file = "/some/path/to/file.json"

local_ip_addresses = wireshark_private_ips(path_to_file)
sniffed_mac_addresses = wireshark_mac_addresses(path_to_file)

print(local_ip_addresses)
[IPv4Address('10.10.0.1'), IPv4Address('10.10.0.101'), IPv4Address('169.254.0.132'),...]

print(sniffed_mac_addresses)
              src_mac                src_mac_company
0   58:B9:65:14:2D:6C                    Apple, Inc.
1   54:AF:97:2D:14:30    TP-Link Corporation Limited
2   90:09:D0:22:41:DE          Synology Incorporated
```

## DISCLAIMER
**This project is in no way affiliated with Wireshark or any of its related services and packages. Any usage of that product is subject to its terms of use.**  

**Once again, do not use `tech-tools` or any other networking tool unless you have received permission to do so.  
This project is not responsible for any misuse or abuse, nor does it condone such practices.**