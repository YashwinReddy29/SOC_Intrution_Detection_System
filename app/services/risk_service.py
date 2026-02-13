def calculate_risk(log, ml_prediction):
    score = 0

    if "Failed login" in log:
        score += 30
    if "High traffic" in log:
        score += 50
    if ml_prediction == 1:
        score += 40

    return min(score, 100)
