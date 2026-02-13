from collections import defaultdict
import time

attack_sequence = defaultdict(list)

def correlate_attack(ip, attack_type):
    current_time = time.time()

    attack_sequence[ip].append((attack_type, current_time))

    # Keep only last 60 seconds
    attack_sequence[ip] = [
        entry for entry in attack_sequence[ip]
        if current_time - entry[1] < 60
    ]

    types = [entry[0] for entry in attack_sequence[ip]]

    if "Failed login" in types and "High traffic" in types:
        return f"⚠️ MULTI-STAGE ATTACK DETECTED from {ip}"

    return None
