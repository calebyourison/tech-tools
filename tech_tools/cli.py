import platform
import subprocess
from ipaddress import IPv4Address, AddressValueError
import threading

import pandas as pd


# IPCONFIG
def ipconfig():
    """Return string of raw ip configuration info from CLI.

    :return: Printout of ipconifg /all on Windows or nmcli device show on linux
    :rtype: str

    Note:
        Use of this function on Linux requires that nmcli be installed.
    """
    operating_system = platform.system().lower()
    # Defaults to windows command
    command = ["ipconfig", "/all"]
    if operating_system == "linux":
        command = ["nmcli", "device", "show"]
    raw_ipconfig = subprocess.run(command, capture_output=True, text=True)
    ipconfig_output = raw_ipconfig.stdout

    return ipconfig_output


def parse_ipconfig():
    """Parse raw ipconfig information and return a list containing a dictionary for each valid interface.

    :return: List of dictionaries with keys: ip, subnet, mac, (gateway if present)
    :rtype: list

    Note:
        Subnet will be provided as a mask on Windows (ex 255.255.255.0) and using CIDR notation on Linux (ex /24).

        Valid interfaces might not have a defined gateway.
    """
    operating_system = platform.system().lower()
    raw_output = ipconfig()
    found_interfaces = []
    # Split by blank lines
    interfaces = raw_output.split("\n\n")

    if operating_system == "linux":
        items_of_interest = {
            "GENERAL.HWADDR": "mac",
            "IP4.ADDRESS[1]": "cidr_notation",
            "IP4.GATEWAY": "gateway",
        }
        for interface in interfaces:
            interface_dict = {}
            lines = interface.splitlines()
            # Replace ': ' with an asterisk as it makes splitting easier in following step, remove whitespace
            lines = [line.replace(": ", "*").replace(" ", "") for line in lines]
            # Create two pieces
            lines = [line.split("*") for line in lines]
            for line in lines:
                # If first piece is a key in items_of_interest
                if line[0] in items_of_interest.keys():
                    # AND second piece isn't a blank value
                    if line[1] != "--":
                        # Use its accompanying value in items_of_interest as its new key, second piece is its value
                        interface_dict[items_of_interest[line[0]]] = line[1]
            found_interfaces.append(interface_dict)

        # Only interfaces with a valid cidr_notation value are desired
        found_interfaces = [
            interface
            for interface in found_interfaces
            if "cidr_notation" in interface.keys()
        ]
        for interface in found_interfaces:
            # Split cidr_notation value into an ip address and a subnet value, remove original cidr_notation pair
            cidr_notation = interface["cidr_notation"]
            splits = cidr_notation.split("/")
            interface["ip"] = splits[0]
            interface["subnet"] = splits[1]
            del interface["cidr_notation"]

    else:
        items_of_interest = {
            "Physical Address": "mac",
            "IPv4 Address": "ip",
            "Subnet Mask": "subnet",
            "Default Gateway": "gateway",
        }
        # Keep lines with IPv4 Address included
        valid_interfaces = [
            interface for interface in interfaces if "IPv4" in interface
        ]

        for interface in valid_interfaces:
            interface_dict = {}
            lines = interface.splitlines()
            # Remove white space to simplify upcoming sections
            stripped_lines = [item.strip() for item in lines]

            for line in stripped_lines:
                # Create two pieces to work with
                line = line.split(":")
                # Replace various undesirable text using multiple steps
                new_line = [line[0].replace(".", "").strip(), line[1].strip()]
                new_line = [
                    item.replace("(Preferred)", "").replace("-", ":")
                    for item in new_line
                ]
                # Check if the first piece is a key in items_of_interest
                if new_line[0] in items_of_interest.keys():
                    # Use its accompanying value in items_of_interest as its new key, second piece is its value
                    interface_dict[items_of_interest[new_line[0]]] = new_line[1]

            found_interfaces.append(interface_dict)

    return found_interfaces


# ARP
def local_arp():
    """Return string of raw ip configuration info from CLI.

    :return: Printout of the local arp table
    :rtype: str
    """
    operating_system = platform.system().lower()
    # Defaults to windows command
    command = ["arp", "-a"]
    if operating_system == "linux":
        command = ["arp", "-n"]
    raw_arp = subprocess.run(command, capture_output=True, text=True)
    arp_output = raw_arp.stdout

    return arp_output


def parse_local_arp():
    """Parse raw local arp data and return a Pandas DataFrame.

    :return: Parsed information from the local arp table, IPv4 Address and Mac Address
    :rtype: Pandas.DataFrame
        columns: ip, mac
    """
    operating_system = platform.system().lower()

    raw_arp_string = local_arp()
    arp_info = raw_arp_string.splitlines()

    # Remove line(s) that contain header information
    arp_info = [
        line.split()
        for line in arp_info
        if "Address" not in line
        if "Interface" not in line
        if len(line) > 1
    ]
    # On windows, the first two items in each list are ip, mac
    selected_items = [[item[0], item[1]] for item in arp_info]

    if operating_system == "linux":
        # On linux, the first and third items are ip, mac
        selected_items = [[item[0], item[2]] for item in arp_info]

    arp_df = pd.DataFrame(selected_items, columns=["ip", "mac"])
    # Convert MAC information to upper case for later comparison to manufacture database.
    arp_df["mac"] = arp_df["mac"].str.upper()
    # Replace - with :
    arp_df["mac"] = arp_df["mac"].str.replace("-", ":")
    # Covert strings to IPv4 Address objects
    arp_df["ip"] = arp_df["ip"].apply(lambda row: IPv4Address(row))

    return arp_df


# Ping
def ping_single_ip(ip, output):
    """Ping a single host and append to output list if successful.

    :param ip: A valid IPv4 Address, example "10.10.10.132"
    :type ip: str, IPv4Address
    :param output: List to update with values
    :type output: list

    :return: Nothing, external list will be updated
    :rtype: None
    """
    operating_system = platform.system().lower()

    # Convert to string if not already
    ip = str(ip)
    # Default to windows command
    command = ["ping", ip]

    # Note the linux ping command requires additional flag to prevent an unending process
    if operating_system == "linux":
        command = ["ping", ip, "-c", "4"]

    ping = subprocess.run(command, capture_output=True, text=True)

    # Note that windows has TTL uppercase
    if "ttl" in ping.stdout.lower():
        output.append(IPv4Address(ip))


def ping_range_ip(ip_list):
    """Ping a list of hosts and return list of hosts that produced a valid response.

    :param ip_list: Containing either str or IPv4Address objects of hosts
    :type ip_list: list

    :return: IPv4Address objects that responded to a ping
    :rtype: list
    """
    output = []
    threads_list = []

    # Create separate thread for each host to expedite the process
    # Most of the time in this function is consumed by waiting for a host response
    for ip in ip_list:
        t = threading.Thread(target=ping_single_ip, args=(ip, output))
        threads_list.append(t)

    for number in range(len(threads_list)):
        threads_list[number].start()

    for number in range(len(threads_list)):
        threads_list[number].join()

    # Sort the output to keep addresses in a user-friendly order
    return sorted(output)


# Trace Route
def trace_route(destination="8.8.8.8"):
    """Determine route from local host to a given destination and return raw string data.

    :param destination: (optional) Remote host, 8.8.8.8 by default
    :type destination: str, IPv4Address

    :return: Printout of tracert on Windows or traceroute on Linux

    Note:
        Use of this function on Linux requires that traceroute be installed.
    """
    operating_system = platform.system().lower()

    # Convert destination to str if not already
    destination = str(destination)

    # Do not resolve hostnames, 100ms timeout to improve speed slightly
    command = ["tracert", "-d", "-w", "100", destination]

    if operating_system == "linux":
        # Do not resolve hostnames, IP information is desirable
        command = ["traceroute", destination, "-n"]

    raw_trace = subprocess.run(command, capture_output=True, text=True)
    trace_output = raw_trace.stdout

    return trace_output


def parse_trace_route_local(destination="8.8.8.8"):
    """Parse raw trace route data into a list of hosts considered to be part of local/private networks.

    :param destination: (optional) Remote host, 8.8.8.8 by default
    :type destination: str, IPv4Address

    :return: Hosts (hops) along a given trace route with local (private) addresses
    :rtype: list
    """

    operating_system = platform.system().lower()

    raw_trace_string = trace_route(destination)

    # Split by lines to dissect the information
    trace_info = raw_trace_string.splitlines()

    if operating_system == "linux":
        # Remove line(s) that contain header information
        trace_info = [
            line.split()
            for line in trace_info
            if "hops" not in line
            if "route" not in line
        ]
        # On linux, the second item contains the IP address
        selected_items = [item[1] for item in trace_info]
    else:
        # Remove unwanted lines beginning and end lines have 'Trac', blank lines will be length of one
        trace_info = [
            line.split() for line in trace_info if "Trac" not in line if len(line) > 1
        ]
        # On windows, the final item will be the IP address
        selected_items = [item[-1] for item in trace_info]

    private_ips = []
    for ip in selected_items:
        try:
            ip_object = IPv4Address(ip)
            # Only local IP addresses are of interest
            if ip_object.is_private:
                private_ips.append(ip_object)

        # Some hosts will return * or similar instead of valid response, except these
        except AddressValueError:
            pass

    return sorted(private_ips)