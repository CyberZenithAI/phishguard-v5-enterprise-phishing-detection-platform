import re

def extract_domains(text):
    return list(set(re.findall(r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)))