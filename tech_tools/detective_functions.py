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


def local_devices(network=None, ports=None):
    """Return a DataFrame containing ip, mac, valid tcp ports, and manufacture information obtained from local network

    :param network: (optional) Interface IP Address, local_ip() by default
    :type network: str, IPv4Address
    :param ports: (optional) TCP ports to scan, should be provided as integers, [80, 443] by default
    :type ports: list

    :return: host ip addresses, mac addresses, valid tcp ports, manufacturing company
    :rtype: Pandas.DataFrame

    Note:
        If no interface address is provided, the function will attempt to locate devices based on the address returned
        from the local_ip() function. If multiple interfaces are present, it is recommended to manually select the preferred one.

        This function requires a valid host ping, as well as a valid entry in the local arp table.  Some hosts might not meet these criteria.

    """
    if network is None:
        network = local_ip()
    local_network = generate_range_from_subnet(network)

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

    # All manufacturing company values will be listed as not_found in case a match is not obtained
    #local_arp_table["company"] = "not_found"

    """for device in local_arp_table["mac"].to_list():
        # Locate the mac prefix within the manufacturer table
        found = [mac for mac in mac_df["mac"].to_list() if device.startswith(mac)]
        if len(found) == 1:
            # Use that prefix to identify the manufacturer
            company = mac_df[mac_df["mac"].isin(found)]["company"].iloc[0]
            # Write that company name into the local_arp_table in the row where the original mac address was located
            local_arp_table["company"] = np.where(
                (local_arp_table["mac"] == device), company, local_arp_table["company"]
            )"""

    return local_arp_table


def semi_local_devices(destination="8.8.8.8", ports=None):
    """Return a DataFrame of ip and TCP port information for Private networks along a designated trace route path.

    :param destination: (optional) Remote host, 8.8.8.8 by default
    :type destination: str, IPv4Address
    :param ports: (optional) TCP ports to scan, should be provided as integers, [80, 443] by default
    :type ports: list

    :return: host ip addresses, valid tcp ports
    :rtype: Pandas.DataFrame

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
