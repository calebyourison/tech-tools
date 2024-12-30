from ipaddress import IPv4Address

import pandas as pd

from tech_tools.utilities import (
    generate_range_from_subnet,
    local_ip,
    tcp_ip_port_scanner,
)

from tech_tools.cli import (
    ping_range_ip,
    parse_local_arp,
    parse_trace_route_local,
)

from tech_tools.resources import mac_lookup


def local_devices(
    network: str | IPv4Address | list[IPv4Address] = None, ports: list[int] = None
) -> pd.DataFrame:
    """Return a DataFrame containing ip, mac, valid tcp ports, and manufacture information obtained from local network

    :param network: (optional) CIDR notation, IP address, or list of IP addresses, will generate a range from local_ip() by default
    :type network: str, IPv4Address, list
    :param ports: (optional) TCP ports to scan, should be provided as integers, [80, 443] by default
    :type ports: list

    :return: host ip addresses, mac addresses, valid tcp ports, manufacturing company
    :rtype: pd.DataFrame

    Note:
        If no interface address is provided, the function will attempt to locate devices based on the address returned
        from the local_ip() function. If multiple interfaces are present, it is recommended to manually select the preferred one.

        Alternatively, the function will accept a list of IPv4 IP Addresses to probe in lieu of an entire subnet.

        Examples of valid input for network param:
            "192.168.0.1/26" <- CIDR notation is preferred to specify the correct subnet
            IPv4Address('10.0.0.1') <- /24 Subnet assumed
            '10.0.0.10' <- /24 Subnet assumed
            ['172.60.20.10', '172.60.20.100', ...]

        This function requires a valid host ping, as well as a valid entry in the local arp table.  Some hosts might not meet these criteria.

    """
    if type(network) is list:
        local_network = network
    elif type(network) is str or type(network) is IPv4Address:
        local_network = generate_range_from_subnet(network)
    else:
        local_network = generate_range_from_subnet(local_ip())

    print("Attempting to gather information for local devices, please wait...")
    successful_pings = ping_range_ip(local_network)

    # Look on supplied tcp ports, using http and https by default
    if ports is None:
        ports = [80, 443]

    successful_tcp_requests = tcp_ip_port_scanner(
        successful_pings, ports=ports, df=False
    )

    local_arp_table = parse_local_arp()

    # Subset arp table df with ip addresses that received valid pings
    local_arp_table = (
        local_arp_table[local_arp_table["ip"].isin(successful_pings)]
        .sort_values(by="ip")
        .reset_index(drop=True)
    )

    # Map ports to dataframe using tcp dictionary
    local_arp_table["ports"] = local_arp_table["ip"].map(successful_tcp_requests)

    local_arp_table["company"] = local_arp_table["mac"].apply(mac_lookup)

    return local_arp_table


def semi_local_devices(
    destination: str | IPv4Address = "8.8.8.8", ports: list[int] = None
) -> pd.DataFrame:
    """Return a DataFrame of ip and TCP port information for Private networks along a designated trace route path.

    :param destination: (optional) Remote host, 8.8.8.8 by default
    :type destination: str, IPv4Address
    :param ports: (optional) TCP ports to scan, should be provided as integers, [80, 443] by default
    :type ports: list

    :return: host ip addresses, valid tcp ports
    :rtype: pd.DataFrame

    Note:
        Assumes /24 subnet, though this might not be correct in many cases.

        Recommended to scan networks individually if subnets of different sizes exist along the trace path.
        A list of local networks along the trace path can be achieved with parse_trace_route_local().
    """
    print("Attempting to gather information for semi-local devices, please wait...")
    # Identify hops with private IP address
    private_ips = parse_trace_route_local(destination)

    # Generate a subnet for each hop, list comprehension to expand for all ip address to scan
    hosts_to_scan = [
        ip for host in private_ips for ip in generate_range_from_subnet(host)
    ]

    # Look on supplied tcp ports, using http and https by default
    if ports is None:
        ports = [80, 443]

    successful_tcp_requests = tcp_ip_port_scanner(hosts_to_scan, ports=ports)

    return successful_tcp_requests
