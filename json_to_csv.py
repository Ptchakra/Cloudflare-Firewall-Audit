import os

files = [file for file in os.listdir() if file.endswith("_rule_event_analytics.json")]

for file in files:
    csv_file = file.replace("_rule_event_analytics.json", ".csv")
    os.system(f"cat {file} | dasel -r json -w csv > csv/{csv_file}")
