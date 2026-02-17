import csv
import json

# Input and Output files
input_file = 'siem_logs_full.csv'

# FIX 1: Use a raw string (r"...") to handle Windows backslashes correctly
# FIX 2: Added the .json extension so the file is usable
output_file = r'C:\Users\Nerus.CS\OneDrive - Coventry University\Desktop\Coventry\Semester 6_2025\Final Year Project\siem_banking_dataset_kathmandu.json'

print(f"Reading {input_file}...")

try:
    # FIX 3: Added encoding='utf-8' to prevent issues with special characters
    with open(input_file, 'r', encoding='utf-8') as csv_file:
        reader = csv.DictReader(csv_file)
        with open(output_file, 'w', encoding='utf-8') as json_file:
            for row in reader:
                # Wazuh needs a JSON object per line
                json.dump(row, json_file)
                json_file.write('\n')
    
    print(f"Success! Data saved to {output_file}")
    
except FileNotFoundError:
    print(f"Error: Could not find {input_file}. Make sure it is in the same folder as this script!")
except OSError as e:
    print(f"Error: Could not write to file. Check permissions or path. Details: {e}")