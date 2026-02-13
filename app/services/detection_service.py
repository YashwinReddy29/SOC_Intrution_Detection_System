from collections import defaultdict

failed_attempts = defaultdict(int)
ddos_tracker = defaultdict(int)

def analyze_log(log):
    if "Failed login" in log:
        ip = log.split()[-1]
        failed_attempts[ip] += 1
        if failed_attempts[ip] > 3:
            return f"🚨 BRUTE FORCE DETECTED from {ip}"

    if "High traffic" in log:
        ip = log.split()[-1]
        ddos_tracker[ip] += 1
        if ddos_tracker[ip] > 3:
            return f"🚨 DDoS DETECTED from {ip}"

    return None
