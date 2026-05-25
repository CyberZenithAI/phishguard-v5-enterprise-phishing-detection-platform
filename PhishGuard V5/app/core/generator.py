import tldextract

def generate(domain):
    ext = tldextract.extract(domain)
    name = ext.domain
    tld = ext.suffix

    variants = set()

    for i in range(len(name)):
        variants.add(name[:i] + name[i+1:] + "." + tld)

    for i in range(len(name)-1):
        s = list(name)
        s[i], s[i+1] = s[i+1], s[i]
        variants.add("".join(s) + "." + tld)

    return list(variants)
