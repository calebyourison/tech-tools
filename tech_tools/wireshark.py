import pandas as pd
from ipaddress import IPv4Address, AddressValueError


wireshark_columns_of_interest = {
    "layers.ip.ip.src_host": "src_ip",
    "layers.eth.eth.src": "src_mac",
    "layers.eth.eth.src_tree.eth.src.oui_resolved": "src_mac_company",
    "layers.ip.ip.dst_host": "dest_ip",
    "layers.frame.frame.protocols": "protocol",
    "layers.frame.frame.coloring_rule.name": "category",
}


def wireshark_extract(file):
    """Return a Series of desired information from a Wireshark JSON file using GroupBy.
    Includes docs_source ip, docs_source mac, docs_source mac company, destination ip, protocol, and category

    :param file: Valid path to a JSON wireshark file
    :type file: str

    :return: Groupby format docs_source ip, docs_source mac, docs_source mac company, destination ip, protocol, and category
    :rtype: Pandas.Series
    """
    raw = pd.read_json(file)

    columns_of_interest = list(wireshark_columns_of_interest.keys())

    # Use columns of interest as meta, select only those columns
    new_df = pd.json_normalize(raw["_source"], meta=columns_of_interest)[
        columns_of_interest
    ]

    # Rename columns
    new_df = new_df.rename(columns=wireshark_columns_of_interest)

    # Basic adjustments, most notably filling blank values
    new_df = new_df.fillna("None")
    new_df["protocol"] = new_df["protocol"].str.replace("eth:ethertype:", "")
    new_df["src_mac"] = new_df["src_mac"].str.upper()

    groupby_object = new_df.groupby(
        ["src_ip", "src_mac", "src_mac_company", "dest_ip", "protocol"]
    )["category"].value_counts()

    return groupby_object


def wireshark_private_ips(file):
    """Return private IP addresses from a Wireshark JSON file

    :param file: Valid path to a Wireshark JSON file
    :type file: str

    :return: IPv4Address objects within the range that falls under the category of Private networks
    :rtype: list
    """
    df = wireshark_extract(file).reset_index()

    source_ips = set(df["src_ip"].tolist())
    destination_ips = set(df["dest_ip"].tolist())
    all_ips = source_ips.union(destination_ips)

    all_private_ips = []
    for ip in all_ips:
        try:
            ip_object = IPv4Address(ip)
            if ip_object.is_private:
                all_private_ips.append(ip_object)
        except AddressValueError:
            pass

    return sorted(all_private_ips)


def wireshark_mac_addresses(file):
    """Return MAC Address/Manufacturer information from a Wireshark JSON file

    :param file: Valid path to a Wireshark JSON file
    :type file: str
    :return: docs_source mac, docs_source mac manufacturing company
    :rtype: Pandas.DataFrame
    """
    source_df = wireshark_extract(file).reset_index()
    groupby_df = (
        source_df.groupby("src_mac")["src_mac_company"].value_counts().reset_index()
    )
    mac_df = groupby_df[["src_mac", "src_mac_company"]]

    return mac_df
