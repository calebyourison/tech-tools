#### 0.2
---
-Addition of `ipconfig()` and `parse_ipconfig()` functions to provide visibility for multiple interfaces.

-Addition of `mac_lookup()` function to determine manufacturing company of mac address 

#### 0.3
---
-Modified `local_devices()` to accept a list of IPv4 Addresses in addition to previous functionality (No Breaking Changes).

-Addition of basic multicast support via `multicast_listen()`. 

-Addition of `quick_start()`, a function that provides automated access to some of the basic package functions.

-Addition of type hints matching docstrings.

#### 0.4
---
-Bug fix `reachable_tcp_single_ip()` where a host provided as str would overwrite existing entry due to mismatched IPv4Address type.

-Modified `ping_single_ip()`, `ping_range_ip()`, and `tcp_ip_port_scanner()` to accept additional timeout parameter (No Breaking Changes).

-Addition of `ping_monitor()`, a function that prints a list of ping responsive hosts at a given frequency.

-Addition of `tcp_ip_port_monitor()` similar to ping monitor; prints a list of hosts with valid responses on a list of ports.