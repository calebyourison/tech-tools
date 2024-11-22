from tech_tools.utilities import (
    generate_range_from_subnet, local_ip, ping_range_ip, parse_local_arp, tcp_ip_port_scanner, trace_route_parse_local)
from tech_tools.resources import mac_df
import numpy as np


def local_devices(network=local_ip(), ports=None):
    """
    Return a DataFrame containing ip, mac, valid tcp ports, and manufacture information obtained from local network

    :param (str) (IPv4Address) (optional) network:
    :param (list) ports:
        Ports should be provided in integer form
    :return (DataFrame):
        columns: ip, mac, ports, company

    """
    local_network = generate_range_from_subnet(network)

    print("Attempting to gather information for local devices, please wait...")
    successful_pings = ping_range_ip(local_network)

    # Look on supplied tcp ports, using http and https by default
    if ports is None:
        ports = [80, 443]

    successful_tcp_requests = tcp_ip_port_scanner(successful_pings, ports=ports, df=False)

    local_arp_table = parse_local_arp()

    # Subset arp table df with ip addresses that received valid pings
    local_arp_table = local_arp_table[local_arp_table['ip'].isin(successful_pings)].sort_values(by='ip').reset_index(drop=True)

    # Map ports to dataframe using tcp dictionary
    local_arp_table['ports'] = local_arp_table['ip'].map(successful_tcp_requests)

    # All manufacturing company values will be listed as not_found in case a match is not obtained
    local_arp_table['company'] = 'not_found'

    for device in local_arp_table['mac'].to_list():
        # Locate the mac prefix within the manufacturer table
        found = [mac for mac in mac_df['mac'].to_list() if device.startswith(mac)]
        if len(found) == 1:
            # Use that prefix to identify the manufacturer
            company = (mac_df[mac_df['mac'].isin(found)]['company'].iloc[0])
            # Write that company name into the local_arp_table in the row where the original mac address was located
            local_arp_table['company'] = np.where((local_arp_table['mac'] == device), company, local_arp_table['company'])

    return local_arp_table


def semi_local_devices(destination='8.8.8.8', ports=None):
    """
    Return a DataFrame of ip and TCP port information for Private networks along a designated trace route path.
        Assumes /24 subnet, though this might not be correct in many cases.
        Recommended to scan networks individually if subnets of different sizes exist along the trace path.

    :param (str) (IPv4Address) (optional) destination:
        Remote host, 8.8.8.8 by default
    :param (list) ports:
    :return (DataFrame):
        columns: ip, ports
    """
    print("Attempting to gather information for semi-local devices, please wait...")
    # Identify hops with private IP address
    private_ips = trace_route_parse_local(destination)

    # Generate a subnet for each hop, list comprehension to expand for all ip address to scan
    hosts_to_scan = [ip for host in private_ips for ip in generate_range_from_subnet(host)]

    # Look on supplied tcp ports, using http and https by default
    if ports is None:
        ports = [80, 443]

    successful_tcp_requests = tcp_ip_port_scanner(hosts_to_scan, ports=ports)

    return successful_tcp_requests
