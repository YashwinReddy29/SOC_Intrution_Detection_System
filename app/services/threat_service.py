def threat_score(ip):
    score = 0

    if ip.endswith("8"):
        score += 20
    if ip.endswith("1"):
        score += 30

    return score
