import re
import json
from collections import Counter

# Load MITRE mapping
with open('mitre_mapping.json') as f:
    mitre_mapping = json.load(f)

# Read log file
with open('auth.log') as file:
    logs = file.readlines()

# Detect events
events = []
for log in logs:
    for key in mitre_mapping:
        if key in log:
            event = mitre_mapping[key]
            event_info = {
                "Log": log.strip(),
                "Tactic": event["Tactic"],
                "Technique": event["Technique"],
                "MITRE ID": event["MITRE ID"]
            }
            events.append(event_info)

# Count Failed Logins from the same IP
failed_ips = []
for event in events:
    if "Failed password" in event["Log"]:
        ip = re.search(r'from (\d+\.\d+\.\d+\.\d+)', event["Log"]).group(1)
        failed_ips.append(ip)

ip_counter = Counter(failed_ips)

# Generate Report
with open("report.txt", "w") as report:
    report.write("=== Security Incident Report ===\n\n")
    for event in events:
        report.write(f"Log: {event['Log']}\n")
        report.write(f"Tactic: {event['Tactic']}\n")
        report.write(f"Technique: {event['Technique']}\n")
        report.write(f"MITRE ID: {event['MITRE ID']}\n\n")
    
    report.write("=== Brute Force Detection Summary ===\n\n")
    for ip, count in ip_counter.items():
        if count >= 5:
            report.write(f"Potential Brute Force Detected from IP: {ip} - {count} failed attempts\n")

print("Report generated: report.txt")