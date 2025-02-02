import re
import pandas as pd

# Define log file paths (Modify as needed)
auth_log_path = "/var/log/auth.log"  # SSH login attempts
apache_log_path = "/var/log/apache2/access.log"  # Web server access logs

# Function to detect SSH brute force attacks
def detect_ssh_bruteforce():
    failed_attempts = {}
    with open(auth_log_path, "r") as log:
        for line in log:
            match = re.search(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)", line)
            if match:
                ip = match.group(1)
                failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

    # Flag IPs with 5 or more failed attempts
    for ip, count in failed_attempts.items():
        if count >= 5:
            print(f"[ALERT] Possible SSH Brute Force: {ip} failed {count} times")

# Function to detect potential DDoS attack
def detect_ddos():
    ip_counts = {}
    with open(apache_log_path, "r") as log:
        for line in log:
            match = re.search(r"(\d+\.\d+\.\d+\.\d+) - - \[", line)
            if match:
                ip = match.group(1)
                ip_counts[ip] = ip_counts.get(ip, 0) + 1

    df = pd.DataFrame(list(ip_counts.items()), columns=["IP", "Requests"])
    suspicious_ips = df[df["Requests"] > 100]  # Flag IPs with >100 requests

    if not suspicious_ips.empty:
        print("[ALERT] Potential DDoS Attack Detected")
        print(suspicious_ips)

# Run detection functions
print("[*] Running Log Analysis...")
detect_ssh_bruteforce()
detect_ddos()
print("[*] Analysis Complete.")
