from tech_tools.utilities import local_ip
import platform
import socket
import struct
import time
from ipaddress import IPv4Address
import re


def multicast_listen(
    multicast_address: str | IPv4Address = "239.255.255.250",
    multicast_port: int = 1900,
    local_host: str | IPv4Address = None,
    duration: int = 15,
    print_raw_data: bool = False,
) -> dict[str, dict[IPv4Address, str]]:
    """Return a IPv4 Address objects along with their MAC addresses (if found) while listening on a given multicast network

    :param multicast_address: (optional) Multicast network broadcast address, 239.255.255.250 SSDP by default
    :type multicast_address: str, IPv4Address
    :param multicast_port: (optional) Port number of multicast network, 1900 SSDP by default
    :type multicast_port: int
    :param local_host: (optional) IPv4 Address of the desired interface, local_ip() by default
    :type local_host: str, IPv4Address
    :param duration: (optional) Time in seconds to scan network, 15 by default
    :type duration: int
    :param print_raw_data: (optional) Display output of scan to console, False by default
    :type print_raw_data: bool

    :return: IPv4Address Objects along with their MAC Addresses if successfully parsed from the raw output
    :rtype: dict

    Note:
        Returned dictionary will be formatted as:

        {'239.255.255.250:1900': {IPv4Address('10.10.172.10'): '00:00:00:00:00:00', ... } }

    """

    multicast_address = str(multicast_address)
    if local_host is None:
        local_host = local_ip()
    local_host = str(local_host)
    operating_system = platform.system().lower()
    data_list = []
    output = {}

    # Define socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_IP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Linux Socket Configuration
    if operating_system == "linux":
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)

        sock.bind((multicast_address, multicast_port))

        sock.setsockopt(
            socket.SOL_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_host)
        )
        sock.setsockopt(
            socket.SOL_IP,
            socket.IP_ADD_MEMBERSHIP,
            socket.inet_aton(multicast_address) + socket.inet_aton(local_host),
        )

    # Windows Socket Configuration
    else:
        sock.bind((local_host, multicast_port))

        mreq = struct.pack(
            "4s4s", socket.inet_aton(multicast_address), socket.inet_aton(local_host)
        )
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    end_time = time.time() + duration

    # Timeout at duration
    sock.settimeout(duration)

    # For duration
    while time.time() < end_time:
        try:
            data_list.append(sock.recvfrom(2048))
            data = sock.recvfrom(2048)
            if print_raw_data is True:
                print(data)
        except TimeoutError:
            pass

    # Unknown MAC unless found using search patterns
    for item in data_list:
        info = item[0]
        mac = "Unknown MAC"

        mac_search_patterns = [
            b'"mac" : "(.*?)",',
            b'"mac":"(.*?)",',
            b"<MAC>(.*?)</MAC>",
        ]

        for search_term in mac_search_patterns:
            mac_search = re.search(search_term, info)
            if mac_search:
                mac = mac_search.group(1).decode("UTF-8")

        host = IPv4Address(item[1][0])

        output[host] = mac

    final_output = {str(multicast_address) + ":" + str(multicast_port): output}

    sock.close()

    return final_output
