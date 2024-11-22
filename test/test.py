import unittest
from ipaddress import IPv4Address

import pandas as pd

from tech_tools.utilities import (local_ip, local_arp, generate_range_from_subnet, generate_range_from_two_ips,
                                  ping_single_ip, reachable_tcp_single_ip, ping_range_ip, tcp_ip_port_scanner,
                                  parse_local_arp, trace_route, trace_route_parse_local)

from tech_tools.wireshark import (wireshark_extract, wireshark_private_ips, wireshark_mac_addresses,
                                  wireshark_columns_of_interest)

from tech_tools.detective_functions import local_devices, semi_local_devices

from tech_tools.resources import json_file

loopback_interface = '127.0.0.1'
google_dns = '8.8.8.8'
invalid_host = '192.0.0.1'


class TestUtilityFunctions(unittest.TestCase):
    """Defines a class to test general utility functions"""

    def test_local_ip(self):
        """Test function to assert local_ip operates correctly"""
        my_ip = local_ip()
        # Assert the function returns an IPv4 Address
        self.assertIsInstance(my_ip, IPv4Address)
        # Assert the loopback interface was not returned
        self.assertFalse(my_ip == IPv4Address('127.0.0.1'))

    def test_local_arp(self):
        """Test function to assert local_ip operates correctly"""
        arp_data = local_arp()
        self.assertIsInstance(arp_data, str)

    def test_parse_local_arp(self):
        """Test function to assert parse_local_arp return as a DataFrame with the correct columns"""
        df = parse_local_arp()
        self.assertIsInstance(df, pd.DataFrame)
        self.assertEqual(sorted(['ip', 'mac']), sorted(df.columns))

    def test_generate_range_from_subnet(self):
        """Test function to assert that generate_range_from_subnet operates correctly"""
        cidr_notation = '192.168.0.0/24'
        standalone_ip = '10.10.10.132'
        subnet_mask = '255.255.255.192'
        subnet_integer = 20

        combinations = [
            cidr_notation,
            (cidr_notation, subnet_integer),
            (cidr_notation, subnet_mask),
            standalone_ip,
            (standalone_ip, subnet_integer),
            (standalone_ip, subnet_mask)
            ]

        # Assert a list is returned, and assert each item within the list is an IPv4Address object
        for argument in combinations:
            if type(argument) is tuple:
                instance = generate_range_from_subnet(*argument)
                self.assertIsInstance(instance, list)
                for ip in instance:
                    self.assertIsInstance(ip, IPv4Address)

            else:
                instance = generate_range_from_subnet(argument)
                self.assertIsInstance(instance, list)
                for ip in instance:
                    self.assertIsInstance(ip, IPv4Address)

    def test_generate_range_from_two_ips(self):
        """Test function to assert generate_range_from_two_ips operates correctly"""
        a = '192.168.0.0'
        b = '192.168.0.255'

        simple_full_subnet = generate_range_from_two_ips(a, b)

        self.assertIsInstance(simple_full_subnet, list)
        self.assertEqual(len(simple_full_subnet), 256)

        for ip in simple_full_subnet:
            self.assertIsInstance(ip, IPv4Address)

        c = '10.10.0.100'
        d = '10.10.15.253'

        large_partial_subnet = generate_range_from_two_ips(c, d)

        self.assertIsInstance(large_partial_subnet, list)
        self.assertEqual(len(large_partial_subnet), 3994)

        for ip in large_partial_subnet:
            self.assertIsInstance(ip, IPv4Address)

    def test_ping_single_ip(self):
        """Test function to assert ping_single_ip operates correctly"""
        hosts = []

        # Use loopback address to account for test on different hardware
        ping_single_ip(loopback_interface, hosts)
        self.assertTrue(IPv4Address(loopback_interface) in hosts)

        # Google is usually accessible, but in the absence of internet access this will fail
        ping_single_ip(google_dns, hosts)
        self.assertTrue(IPv4Address(google_dns) in hosts)

        # This IP SHOULD fail in most circumstances
        ping_single_ip(invalid_host, hosts)
        self.assertTrue(IPv4Address(invalid_host) not in hosts)

    def test_reachable_tcp_single_ip(self):
        """Test function to assert reachable_tcp_single_ip operates correctly"""
        my_host_dict = {}
        # Google, if internet is not available this test will fail
        reachable_tcp_single_ip(google_dns, 53, my_host_dict)
        self.assertTrue(IPv4Address(google_dns) in my_host_dict.keys())
        self.assertTrue(53 in my_host_dict[IPv4Address(google_dns)])

    def test_ping_range_ip(self):
        """Test function to assert ping_range_ip operates correctly"""

        # Loopback interface and local ip should be available, google only with valid internet
        expected_valid_hosts = [local_ip(), loopback_interface, google_dns]

        # Difficult to guarantee an invalid ping, but this address doesn't exist on many networks
        invalid_hosts = [invalid_host]

        hosts = expected_valid_hosts + invalid_hosts

        valid_pings = ping_range_ip(hosts)

        # Should return a list, same length as expected_valid_hosts
        self.assertIsInstance(valid_pings, list)
        self.assertEqual(len(expected_valid_hosts), len(valid_pings))

        # Confirm valid pings are IPv4 objects
        for ip in valid_pings:
            self.assertIsInstance(ip, IPv4Address)

        # Check to make sure the expected hosts are present (or not present)
        for ip in expected_valid_hosts:
            self.assertTrue(IPv4Address(ip) in valid_pings)

        for ip in invalid_hosts:
            self.assertTrue(IPv4Address(ip) not in valid_pings)

    def test_ip_port_scanner(self):
        """Test function to assert ip_port_scanner operates correctly"""
        hosts = [loopback_interface, google_dns]
        port = 53
        ports = [53, 80]

        # Google DNS should be a valid connection on port 53
        single_port = tcp_ip_port_scanner(hosts, port, df=False)

        self.assertIsInstance(single_port, dict)

        # Should only be one item in dict
        self.assertTrue(len(single_port) == 1)
        # Google_dns should be in the keys
        self.assertTrue(IPv4Address(google_dns) in single_port.keys())
        # Port 53 should be the only port
        self.assertTrue(len(single_port[IPv4Address(google_dns)]) == 1)
        self.assertTrue(53 in single_port[IPv4Address(google_dns)])

        # Google DNS should be a valid connection on port 53, same test, just providing a list of ports
        multi_ports = tcp_ip_port_scanner(hosts, ports, df=False)

        self.assertIsInstance(multi_ports, dict)

        # Should only be one item in dict
        self.assertTrue(len(multi_ports) == 1)
        # Google_dns should be in the keys
        self.assertTrue(IPv4Address(google_dns) in multi_ports.keys())
        # Port 53 should be the only port
        self.assertTrue(len(multi_ports[IPv4Address(google_dns)]) == 1)
        self.assertTrue(53 in multi_ports[IPv4Address(google_dns)])

        # Assertions when a DataFrame is returned, both should be equal given the input
        single_port_df = tcp_ip_port_scanner(hosts, port, df=True)
        multi_port_df = tcp_ip_port_scanner(hosts, ports, df=True)
        dfs = [single_port_df, multi_port_df]
        for df in dfs:
            self.assertIsInstance(df, pd.DataFrame)
            self.assertEqual(sorted(['ip', 'ports']), sorted(df.columns))
            self.assertEqual(1, df.shape[0])
            self.assertTrue(IPv4Address(google_dns) in df['ip'].tolist())
            self.assertTrue(53 in df['ports'].tolist()[0])



    def test_trace_route(self):
        """Test Function to assert trace_route operates correctly"""
        trace_route_output = trace_route()
        self.assertIsInstance(trace_route_output, str)

    def test_trace_route_parse_local(self):
        """Test function to assert that trace_route_parse_local returns a list of Private IPv4Address objects"""
        local_ips = trace_route_parse_local()
        self.assertIsInstance(local_ips, list)
        for ip in local_ips:
            self.assertIsInstance(ip, IPv4Address)
            self.assertTrue(ip.is_private)


class TestWiresharkFunctions(unittest.TestCase):
    """Defines a class to test wireshark functions"""

    def test_wireshark_extract(self):
        """Test function to assert wireshark_extract returns a series"""
        groupby_object = wireshark_extract(json_file)
        self.assertIsInstance(groupby_object, pd.Series)

        # Reset index to convert to Dataframe, ensure correct columns
        df = groupby_object.reset_index()
        expected_columns = list(wireshark_columns_of_interest.values()) + ['count']
        self.assertEqual(sorted(expected_columns), sorted(df.columns))

    def test_wireshark_private_ips(self):
        """Test function to assert wireshark_private_ips returns a list of Private IPv4Address Objects"""
        local_ips = wireshark_private_ips(json_file)
        self.assertIsInstance(local_ips, list)
        for ip in local_ips:
            self.assertIsInstance(ip, IPv4Address)
            self.assertTrue(ip.is_private)

    def test_wireshark_mac_addresses(self):
        """Test Function to assert wireshark_mac_addresses returns a DataFrame with the correct columns"""
        df = wireshark_mac_addresses(json_file)
        self.assertIsInstance(df, pd.DataFrame)
        self.assertEqual(sorted(['src_mac', 'src_mac_company']), sorted(df.columns))


class TestDetectiveFunctions(unittest.TestCase):
    """Defines a class to test detective functions"""

    def test_local_devices(self):
        """Test function to assert local_devices returns a DataFrame with the correct columns"""
        df = local_devices()
        self.assertIsInstance(df, pd.DataFrame)
        self.assertEqual(sorted(['ip', 'mac', 'ports', 'company']), sorted(df.columns))

    def test_semi_local_devices(self):
        """Test function to assert semi_local_devices returns a DataFrame with
                private IPv4 Address objects in the ip column
                list of ports in the ports column"""

        df = semi_local_devices()

        self.assertIsInstance(df, pd.DataFrame)
        self.assertEqual(sorted(['ip', 'ports']), sorted(df.columns))

        ips = df['ip'].tolist()
        for ip in ips:
            self.assertIsInstance(ip, IPv4Address)
            self.assertTrue(ip.is_private)

        ports_column = df['ports'].tolist()
        for list_of_ports in ports_column:
            self.assertIsInstance(list_of_ports, list)
            for port in list_of_ports:
                self.assertIsInstance(port, int)
