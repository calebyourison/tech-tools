import pandas as pd
from importlib.resources import files

file_path = "tech_tools.files"

# Manufacturer Mac Address list, loaded as a DataFrame with three columns
# For use in referencing what entity a mac address belongs to
mac_file = str(files(file_path).joinpath("mac.txt"))
mac_df = pd.read_table(
    mac_file, header=None, names=["mac", "company", "company_long"], on_bad_lines="warn"
)
# Remove whitespace from columns
mac_df["mac"] = mac_df["mac"].str.strip()
mac_df["company"] = mac_df["company"].str.strip()

# Mini JSON file for testing
json_file = str(files(file_path).joinpath("wireshark.json"))

def mac_lookup(mac_address):
    """Return the manufacturing company for a given host mac address, "not_found" for failed matches.

    :param mac_address: Host mac address, example "00:1A:2B:3C:4D:5E"
    :type mac_address: str

    :return: Manufacturing company
    :rtype: str
    """
    company = 'not_found'
    # Convert to uppercase
    mac_address = mac_address.upper()
    # Replace '-' with ':'
    mac_address = mac_address.replace('-', ':')

    found = [mac for mac in mac_df["mac"].to_list() if mac_address.startswith(mac)]
    if len(found) == 1:
        # Use that prefix to identify the manufacturer
        company = mac_df[mac_df["mac"].isin(found)]["company"].iloc[0]

    return  company
