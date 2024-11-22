import pandas as pd
from importlib.resources import files

file_path = "tech_tools.files"

# Manufacturer Mac Address list, loaded as a DataFrame with three columns
# For use in referencing what entity a mac address belongs to
mac_file = str(files(file_path).joinpath('mac.txt'))
mac_df = pd.read_table(mac_file, header=None, names=['mac', 'company', 'company_long'], on_bad_lines='warn')
# Remove whitespace from columns
mac_df['mac'] = mac_df['mac'].str.strip()
mac_df['company'] = mac_df['company'].str.strip()

# Mini JSON file for testing
json_file = str(files(file_path).joinpath('wireshark.json'))
