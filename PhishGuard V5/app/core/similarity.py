import Levenshtein

def similarity(a, b):
    return 1 - (Levenshtein.distance(a, b) / max(len(a), len(b)))