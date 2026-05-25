def score(result, sim):
    s = 0
    if result["active"]:
        s += 50
    if result["mx"]:
        s += 30
    if sim > 0.8:
        s += 20
    return min(s, 100)
