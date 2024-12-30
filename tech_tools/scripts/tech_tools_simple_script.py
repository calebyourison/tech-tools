from tech_tools.cli import parse_ipconfig, ping_range_ip
from tech_tools.detective_functions import local_devices
from tech_tools.utilities import (
    generate_range_from_subnet,
    tcp_ip_port_scanner,
    local_ip,
)
from tech_tools.wireshark import (
    wireshark_private_ips,
    wireshark_mac_addresses,
    wireshark_extract,
)
import warnings

warnings.simplefilter(action="ignore", category=FutureWarning)


def print_list_n_items_per_line(item_list, n):
    current_line = [str(item) for item in item_list[0:n]]
    print(", ".join(current_line))
    updated_list = item_list[n:]
    if len(updated_list) >= n:
        print_list_n_items_per_line(updated_list, n)
    else:
        print(", ".join([str(item) for item in updated_list]))


def port_from_user_input(list_of_user_defined_ports):
    while True:
        port = input('\nPlease enter a port number or "done" to continue:\n')
        if port == "done":
            break
        try:
            port = int(port)
            if 65536 > port > 0:
                list_of_user_defined_ports.append(port)
            else:
                print("\nYou did not provide a valid port number between 1 and 65535")

        except ValueError:
            print("\nYour entry was not number")


def list_of_ports_from_user_input(list_of_user_defined_ports):
    port_from_user_input(list_of_user_defined_ports)

    # Eliminate any duplicates, sort
    list_of_user_defined_ports = sorted(list(set(list_of_user_defined_ports)))

    if len(list_of_user_defined_ports) > 0:
        print("You have selected these ports: \n", list_of_user_defined_ports)
        completed = input("\nAre you satisfied with this list? (y/n)")
        if completed.lower() == "y":
            pass
        else:
            list_of_ports_from_user_input(list_of_user_defined_ports)
    else:
        print("\nYou must provide at least one port")
        list_of_ports_from_user_input(list_of_user_defined_ports)

    return list_of_user_defined_ports


def network_information_from_user_input():
    user_input = input(
        "\nPlease provide network information in one of the following formats: "
        "\nCIDR Notation: 192.168.0.1/26 "
        "\nIP Address, Subnet: 192.168.0.1 , 255.255.255.0"
        "\nUnknown Subnet: 192.168.0.1 (This will assume 255.255.255.0) \n"
    )

    if "/" in user_input:
        splits = user_input.split("/")
        user_input = (splits[0].strip(), splits[1].strip())
    elif "," in user_input:
        splits = user_input.split(",")
        user_input = (splits[0].strip(), splits[1].strip())

    elif " " in user_input:
        splits = user_input.split(" ")
        # Multiple spaces will result in more than two pieces, eliminate them
        splits = [split for split in splits if len(split) > 1]
        user_input = (splits[0].strip(), splits[1].strip())

    else:
        user_input = (user_input, 24)

    try:
        user_input = generate_range_from_subnet(*user_input)

    except ValueError:
        print("Invalid input please try again")
        user_input = network_information_from_user_input()

    print("You have selected the following list of IPv4 Addresses: \n")

    print_list_n_items_per_line(user_input, 5)

    approval = input("\nAre you satisfied with this list? (y/n)")

    if approval.lower() == "y":
        pass
    else:
        user_input = network_information_from_user_input()

    return user_input


def validate_wireshark_filepath():
    filepath = input(
        "\nPlease provide your JSON file path or 'quit' to return to the Wireshark menu\n"
    )

    if filepath == "quit":
        pass

    else:
        try:
            wireshark_extract(filepath)
        except (ValueError, FutureWarning):
            print("\nError, did you provide a valid path to a Wireshark JSON file?")
            validate_wireshark_filepath()
        except FileNotFoundError:
            print("\nError File Not Found")
            validate_wireshark_filepath()

        return filepath


def local_devices_script_function():
    print(
        "\nSelect: \n1 for auto (primary interface/24 on ports 80 and 443) \n2 for manual settings \n3 to quit \n"
    )
    auto_or_manual = input("")
    if auto_or_manual == "1":
        print("\n", local_devices())

    elif auto_or_manual == "2":
        print(
            "\nYou have selected manual settings. We need to gather some information:"
        )
        user_provided_network_information = network_information_from_user_input()
        starting_ports_list = []
        user_provided_ports = list_of_ports_from_user_input(starting_ports_list)
        print(
            "\n",
            local_devices(
                network=user_provided_network_information, ports=user_provided_ports
            ),
        )

    elif auto_or_manual == "3":
        print("Returning to main menu")

    else:
        print("Invalid selection")
        local_devices_script_function()


def tcp_port_scanner_script_function():
    print(
        "\nSelect: \n1 for auto (primary interface/24 on ports 80 and 443) \n2 for manual settings \n3 to quit \n"
    )
    auto_or_manual = input("")
    if auto_or_manual == "1":
        print("Scanning...")
        network = generate_range_from_subnet(local_ip())
        ports = [80, 443]
        print("\n", tcp_ip_port_scanner(ip_list=network, ports=ports))

    elif auto_or_manual == "2":
        print(
            "\nYou have selected manual settings. We need to gather some information:"
        )
        network = network_information_from_user_input()
        starting_ports = []
        ports = list_of_ports_from_user_input(starting_ports)
        print("Scanning...")
        print("\n", tcp_ip_port_scanner(ip_list=network, ports=ports))

    elif auto_or_manual == "3":
        print("Returning to main menu")

    else:
        print("Invalid selection")
        tcp_port_scanner_script_function()


def wireshark_analysis_script_function():
    print(
        "\nIf you have not done so already: "
        "\n   a. Capture packets using Wireshark"
        "\n   b. Export packet dissections as JSON"
        "\n   c. Make a note of the file path (ex: C:\\Users\\JohnSmith\\Documents\\wireshark_info.json)"
        '\n       tip: On Windows, right click on the file, select "Properties", select "Security" copy the filepath'
    )

    print(
        "\nSelect "
        "\n1 to find local addresses "
        "\n2 to find mac addresses "
        "\n3 to quit \n"
    )

    user_input = input("")

    if user_input == "1":
        filepath = validate_wireshark_filepath()
        if filepath:
            print("\nLocal addresses in your packet capture file: \n")
            private_ips = [str(ip) for ip in wireshark_private_ips(filepath)]
            print_list_n_items_per_line(private_ips, 5)
        else:
            wireshark_analysis_script_function()

    elif user_input == "2":
        filepath = validate_wireshark_filepath()
        if filepath:
            print("\nMac addresses in your packet capture file: \n")
            print(wireshark_mac_addresses(filepath))
        else:
            wireshark_analysis_script_function()

    elif user_input == "3":
        print("Returning to main menu")

    else:
        print("Invalid selection")
        wireshark_analysis_script_function()


def ping_range_script_function():
    print(
        "Select"
        "\n1 Auto: Ping all devices on /24 using the primary interface"
        "\n2 Ping a user defined network"
        "\n3 quit \n"
    )

    user_input = input("")

    valid_pings = None

    if user_input == "1":
        print("Please Wait...")
        valid_pings = ping_range_ip(generate_range_from_subnet(local_ip()))

    elif user_input == "2":
        user_defined_network = network_information_from_user_input()
        print("Please Wait...")
        valid_pings = ping_range_ip(user_defined_network)

    elif user_input == "3":
        print("Returning to main menu")

    else:
        print("Invalid selection")
        ping_range_script_function()

    if valid_pings:
        print("valid Pings: \n")
        for host in valid_pings:
            print(host)


def display_interfaces():
    print(
        "\nPlease reference this network information for your current device interface(s): "
    )
    for interface in parse_ipconfig():
        print("------------")
        for key, value in interface.items():
            print(key, ": ", value)
        print("------------")


def user_selection():
    valid_selections = [1, 2, 3, 4, 5, 6]

    print(
        "\nPlease select from the following options: "
        "\n 1 Probe Local Devices "
        "\n 2 TCP Port Scanner "
        "\n 3 Wireshark Analysis"
        "\n 4 Display Interfaces"
        "\n 5 Ping IP range"
        "\n 6 Quit"
    )

    user_input = input("\n")

    try:
        user_input_int = int(user_input)

        if user_input_int in valid_selections:
            pass

        else:
            print("Invalid Selection")
            user_input_int = user_selection()

    except ValueError:
        print("Invalid Input")
        user_input_int = user_selection()

    return user_input_int


def tech_tools_script_function():
    print("\nMAIN MENU")

    user_input = user_selection()

    if user_input == 1:
        print("You have chosen to probe local devices")
        local_devices_script_function()

    elif user_input == 2:
        print("You have chosen to scan tcp ports")
        tcp_port_scanner_script_function()

    elif user_input == 3:
        print("You have chosen Wireshark analysis")
        wireshark_analysis_script_function()

    elif user_input == 4:
        display_interfaces()

    elif user_input == 5:
        print("You have chosen Ping IP Range")
        ping_range_script_function()

    elif user_input == 6:
        print("End")

    return user_input


def quick_start():
    user_choice = tech_tools_script_function()
    while user_choice != 6:
        user_choice = tech_tools_script_function()
