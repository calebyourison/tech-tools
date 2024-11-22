import socket
import subprocess
import threading
from ipaddress import IPv4Address, IPv4Network, AddressValueError
import platform

import pandas as pd

# set display options
pd.options.display.max_columns = 40
pd.options.display.width = 120
pd.set_option("max_colwidth", 400)

# General information
def local_ip():
    """
    Return local IPv4Address by way of attempting a socket connection to determine primary interface.
        Unsuccessful socket attempt will return 127.0.0.1.

    :return (IPv4Address):

    Note: This function attempts to forge a connection via the 'primary' interface, in the event that multiple valid
        interfaces are online, the result may be undesirable.  Either disable other interfaces, or determine local ip
        via other means.

        If using a statically defined IP address (for instance, while connecting to an offline, unmanaged switch) it is
        highly recommended to supply an address, subnet, and gateway.  Omission of this information could prevent a
        valid socket attempt and default to the fallback interface.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        # This connection does not need to be successful
        s.connect(('10.254.254.254', 1))
        ip = IPv4Address(s.getsockname()[0])
    # Fallback to loopback address, notify user
    except (PermissionError, ConnectionRefusedError, OSError):
        ip = '127.0.0.1'
        print('Unable to determine local address: defaulting to loopback interface')
    finally:
        s.close()
    return ip

def local_arp():
    """
    Return raw local arp data

    :return (str):
    """
    operating_system = platform.system().lower()
    # Defaults to windows command
    command = ['arp', '-a']
    if operating_system  == 'linux':
        command = ['arp', '-n']
    raw_arp = subprocess.run(command, capture_output=True, text=True)
    arp_output = raw_arp.stdout

    return arp_output

def parse_local_arp():
    """
    Parse raw local arp data into a Pandas DataFrame

    :return (DataFrame):
        columns: ip, mac
    """
    operating_system = platform.system().lower()

    raw_arp_string = local_arp()
    arp_info = raw_arp_string.splitlines()

    # Remove line(s) that contain header information
    arp_info = [line.split() for line in arp_info if 'Address' not in line if 'Interface' not in line if len(line) > 1]
    # On windows, the first two items in each list are ip, mac
    selected_items = [[item[0], item[1]] for item in arp_info]

    if operating_system == 'linux':
        # On linux, the first and third items are ip, mac
        selected_items = [[item[0], item[2]] for item in arp_info]

    arp_df = pd.DataFrame(selected_items, columns=['ip', 'mac'])
    # Convert MAC information to upper case for later comparison to manufacture database.
    arp_df['mac'] = arp_df['mac'].str.upper()
    # Replace - with :
    arp_df['mac'] = arp_df['mac'].str.replace('-', ':')
    # Covert strings to IPv4 Address objects
    arp_df['ip'] = arp_df['ip'].apply(lambda row: IPv4Address(row))

    return arp_df

# IP address lists
def generate_range_from_subnet(ip, subnet=24):
    """
    Return a list of IPv4 Address objects based on provided subnet information, excludes network and broadcast addresses

    :param (str) (IPv4Address) ip:
        Accepts the following formats:
            str (CIDR notation optional):  "10.0.0.101", "10.10.10.0/24"
            IPv4: IPv4Address("192.168.0.39")

    :param (str) (int) (optional) subnet:
        Accepts the following:
            int subnet = 24
            str subnet = "255.255.255.0"

    :return (list):
        Containing IPv4 Address objects based upon that subnet ip range, excluding network and broadcast addresses

    Note:
        If subnet is not referenced in either the ip or subnet params, function assumes 24 or (255.255.255.0)
        CIDR notation in ip param overrides subnet param

        The following are examples of valid inputs:
            generate_range_from_subnet("10.0.0.1) <- assumption of 255.255.255.0 or 24
            generate_range_from_subnet(IPv4Address("192.168.10.10")) <- assumption of 255.255.255.0 or 24
            generate_range_from_subnet("192.168.5.1/25")
            generate_range_from_subnet("192.168.0.1", 23)
            generate_range_from_subnet("10.10.2.0", "255.255.254.0")

    """
    # Convert both parameters to string for evaluation
    ip = str(ip)
    subnet = str(subnet)

    # CIDR notation overrides subnet param
    if '/' in ip:
        network_info = ip

    # Otherwise check what format the subnet info is provided in
    else:
        # Subnet mask form
        if '.' in subnet:
            network_info = (ip, subnet)
        # As a last resort, the function will create CIDR notation from the subnet integer value
        else:
            network_info = ip + '/' + subnet

    # Not using strict for simplicity to allow for any IP address to pass
    network = IPv4Network(network_info, strict=False)
    network_hosts = [host for host in network.hosts()]

    return network_hosts


def generate_range_from_two_ips(first_ip, second_ip):
    """
    Return a list of IPv4 Address objects between two provided IPs, includes provided addresses

    :param (str) (IPv4Address) first_ip:
        example: "10.10.10.132"

    :param (str) (IPv4Address) second_ip:
        example: IPv4Address("10.20.40.12")

    :return (list):
        Includes both addresses along with every possible address in between them with complete disregard for subnet
    """
    # Convert to IPv4 objects if not already
    first_ip = IPv4Address(first_ip)
    second_ip = IPv4Address(second_ip)

    starting_ip = first_ip
    ending_ip = second_ip
    # Ensure a proper range is created by starting with smaller IP address
    if first_ip > second_ip:
        starting_ip = second_ip
        ending_ip = first_ip

    # List will be inclusive of ending IP
    # Converting to integers allows for a comprehension as the addresses are translated to basic numbers
    ip_list = [IPv4Address(ip) for ip in range(int(starting_ip), int(ending_ip) + 1)]

    return ip_list


# Single Host commands
def ping_single_ip(ip, output):
    """
    Ping a single IP address and append to output list if successful

    :param (str) (IPv4Address) ip:
        example: "10.34.1.1"

    :param (list) output:
        list to be updated

    :return:
        Nothing, external list will be updated
    """
    operating_system = platform.system().lower()

    # Convert to string if not already
    ip = str(ip)
    # Default to windows command
    command = ['ping', ip]

    # Note the linux ping command requires additional flag to prevent an unending process
    if operating_system == 'linux':
        command = ['ping', ip, '-c', '4']

    ping = subprocess.run(command, capture_output=True, text=True)

    # Note that windows has TTL uppercase
    if 'ttl' in ping.stdout.lower():
        output.append(IPv4Address(ip))


def reachable_tcp_single_ip(host, port, output, timeout=4):
    """
    Determine if a given host on a given port is reachable via TCP socket connection, add successful values to dictionary

    :param (str) (IPv4Address) host:
        example: "10.10.0.1"

    :param (int) port:
        example: 80

    :param (dict) output:
        reachable hosts will be added to this dict in the format: {IP4Address: [port], IPv4Address: [port1, port2], ...}

    :param (int) timeout:
        seconds to wait for timeout (failure)

    :return:
        Nothing, external dictionary will be updated

    Note:
        If host is already present within the dictionary, the port will be appended to the existing list
        However, if the port in question already exists within said list, it will not be added to avoid duplicates
    """
    # Define socket type, IPv4, TCP
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Timeout interval
    soc.settimeout(timeout)

    # If connection is successful, create entry for host/port or append port to list of ports if entry already exists
    try:
        soc.connect((str(host), int(port)))
        soc.shutdown(socket.SHUT_RDWR)
        if host in output.keys():
            # Prevent duplicate port listings in the event of multiple attempts
            if port not in output[host]:
                output[IPv4Address(host)].append(port)
        else:
            output[IPv4Address(host)] = [port]

    except (TimeoutError, ConnectionRefusedError, OSError):
        pass

    finally:
        soc.close()


# Multi Host commands
def ping_range_ip(ip_list):
    """
    Ping a list of addresses and return list of hosts that produced a valid response

    :param (list) ip_list:
        Containing either str or IPv4Address objects of hosts

    :return (list):
         Containing IPv4Address objects that responded to a ping
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


def tcp_ip_port_scanner(ip_list, ports, df=True):
    """
    Determine which hosts from a given list are reachable via a port or list of ports, return dictionary or DataFrame
        of valid connections

    :param (list) ip_list:
        Containing either str ip "10.10.1.1" or IPv4Address("10.10.1.1") objects

    :param (int) (list) ports:
        Either a single int port or list of int ports

    :param (bool) (optional) df:
        This entry will determine what format is returned, True by default and therefore a DataFrame.

    :return (dict) or (DataFrame):
        Formatted as: {IPv4Address("10.10.1.1"): [80, 443], ...}
        or
        DataFrame with columns: ip, ports

    """
    port_list = []

    # Determine if single port or multiple ports were provided, append/extend port_list accordingly

    if type(ports) is int:
        port_list.append(ports)
    elif type(ports) is list:
        port_list.extend(ports)

    threads_list = []
    output = {}

    # Create separate thread for each host to expedite the process
    # Most of the time in this function is consumed by waiting for a host response
    for ip in ip_list:
        for port in port_list:

            t = threading.Thread(target=reachable_tcp_single_ip, args=(ip, port, output))
            threads_list.append(t)

    for number in range(len(threads_list)):
        threads_list[number].start()

    for number in range(len(threads_list)):
        threads_list[number].join()

    # Sort output to start with the lowest ip, sort each list of ports as well
    final_output = {ip: sorted(output[ip]) for ip in sorted(output.keys())}

    if df is True:
        pre_df_dictionary = {'ip': [ host for host in final_output.keys()], 'ports': [ports for ports in final_output.values()]}
        final_output = pd.DataFrame.from_dict(pre_df_dictionary)

    return final_output


# Trace Route
def trace_route(destination='8.8.8.8'):
    """
    Determine route from local host to a given destination and return raw string data

    :param (str) (IPv4Address) (optional) destination:
        Remote host, 8.8.8.8 by default

    :return (str):
    """
    operating_system = platform.system().lower()

    # Convert destination to str if not already
    destination = str(destination)

    # Do not resolve hostnames, 100ms timeout to improve speed slightly
    command = ['tracert', '-d', '-w', '100', destination]

    if operating_system == 'linux':
        # Do not resolve hostnames, IP information is desirable
        command = ['traceroute', destination, '-n']

    raw_trace = subprocess.run(command, capture_output=True, text=True)
    trace_output = raw_trace.stdout

    return trace_output

def trace_route_parse_local(destination='8.8.8.8'):
    """
    Parse raw trace route data into a list that includes IP address information for hosts considered to be
        part of "local" or "private" networks.  Exclude "public" networks.

    :param (str) (IPv4Address) (optional) destination:
        Remote host, 8.8.8.8 by default

    :return (list):
    """

    operating_system = platform.system().lower()

    raw_trace_string = trace_route(destination)

    # Split by lines to dissect the information
    trace_info = raw_trace_string.splitlines()

    if operating_system == 'linux':
        # Remove line(s) that contain header information
        trace_info = [line.split() for line in trace_info if 'hops' not in line if 'route' not in line]
        # On linux, the second item contains the IP address
        selected_items = [item[1] for item in trace_info]
    else:
        # Remove unwanted lines beginning and end lines have 'Trac', blank lines will be length of one
        trace_info = [line.split() for line in trace_info if 'Trac' not in line if len(line) > 1]
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
