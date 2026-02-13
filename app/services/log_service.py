import random
from datetime import datetime

# Simulated internal IP range
ips = [
    # North America
    "8.8.8.8",            # USA
    "13.107.21.200",      # USA
    "104.244.42.1",       # USA

    # Europe
    "91.198.174.192",     # Netherlands
    "185.199.108.153",    # Germany
    "51.158.68.68",       # France
    "5.79.68.161",        # UK

    # Asia
    "210.245.31.35",      # Vietnam
    "203.208.60.1",       # China
    "103.21.244.0",       # India

    # Middle East
    "94.187.75.5",        # UAE
    "82.102.16.23",       # Turkey

    # South America
    "200.160.2.3",        # Brazil
    "181.30.108.5",       # Argentina

    # Africa
    "41.77.51.1",         # South Africa
    "102.67.65.1",        # Nigeria

    # Australia
    "1.1.1.1"             # Australia
]

def generate_log():
    """
    Generates a simulated SOC log entry.
    """

    log_type = random.choice(["normal", "failed_login", "ddos"])
    ip = random.choice(ips)
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    if log_type == "normal":
        message = f"INFO: Successful login from {ip}"
    elif log_type == "failed_login":
        message = f"WARNING: Failed login attempt from {ip}"
    else:
        message = f"ALERT: High traffic detected from {ip}"

    return f"[{timestamp}] {message}"
