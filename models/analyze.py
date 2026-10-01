"""Feature extraction for LinkShield (36 lexical URL features)."""
import math
import re
from urllib.parse import urlparse

RISKY_TLDS = [".xyz", ".ru", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".work", ".click"]
TRUSTED_TLDS = [".gov", ".edu", ".gov.sa", ".edu.sa", ".gov.uk", ".ac.uk", ".gov.au"]
SHORTENERS = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly", "short.url"]


def shannon_entropy(text):
    if not text:
        return 0
    prob = [text.count(c) / len(text) for c in dict.fromkeys(text)]
    return round(-sum(p * math.log2(p) for p in prob), 3)


def has_ip(url):
    return 1 if re.search(r"(\d{1,3}\.){3}\d{1,3}", url) else 0


def extract_features(url, result):
    """Return a list of 36 features + the label, or None for malformed URLs."""
    url = str(url).lower().strip()
    url = url.replace("https://", "").replace("http://", "").rstrip("/")
    if url.startswith("www."):
        url = url[4:]

    # Remember '@' before dropping it: user@host -> host
    has_at_sign = 1 if "@" in url else 0
    if has_at_sign:
        url = url.split("@")[-1]

    if url.count("[") != url.count("]"):  # malformed IPv6
        return None
    try:
        parsed = urlparse("http://" + url)
        host = parsed.hostname or ""
    except ValueError:
        return None
    path = parsed.path or ""
    query = parsed.query or ""

    features = [
        len(url),                                                   # url_length
        len(host),                                                  # hostname_length
        len(path),                                                  # path_length
        len(query),                                                 # query_length
        url.count("."),                                             # dot_count
        url.count("-"),                                             # hyphen_count
        url.count("_"),                                             # underscore_count
        url.count("/"),                                             # slash_count
        url.count("?"),                                             # question_count
        url.count("="),                                             # equal_count
        has_at_sign,                                                # at_count
        url.count("&"),                                             # ampersand_count
        url.count("%"),                                             # percent_count
        url.count("#"),                                             # hash_count
        sum(c.isdigit() for c in url),                              # digit_count
        sum(c.isdigit() for c in host),                             # host_digit_count
        sum(c.isdigit() for c in path),                             # path_digit_count
        round(sum(c.isdigit() for c in host) / max(len(host), 1), 4),  # digit_ratio
        host.count("."),                                            # host_dot_count
        max(host.count(".") - 1, 0),                                # subdomain_count
        path.count("/"),                                            # path_slash_count
        1 if "//" in path else 0,                                   # has_double_slash
        1 if "../" in path else 0,                                  # has_parent_dir
        len(query.split("&")) if query else 0,                      # query_params_count
        has_ip(url),                                                # has_ip
        1 if any(host.endswith(t) for t in RISKY_TLDS) else 0,      # risky_tld
        1 if any(s in host for s in SHORTENERS) else 0,             # shortener
        shannon_entropy(url),                                       # url_entropy
        shannon_entropy(host),                                      # host_entropy
        max(url.count(c) for c in set(url)) if url else 0,          # max_char_repeat
        sum(c in "?=&@%" for c in url) / max(len(url), 1),          # special_char_ratio
        sum(c in "aeiou" for c in host) / max(len(host), 1),        # vowel_ratio
        1 if any(host.endswith(t) for t in TRUSTED_TLDS) else 0,    # trusted_tld
        host.count("-"),                                            # host_hyphen_count
        len(host.split("-")),                                       # host_word_count
        max([len(w) for w in re.split(r"[-.]", host)] or [0]),      # max_word_length
    ]
    features.append(int(result))
    return features


FEATURE_NAMES = [
    "url_length", "hostname_length", "path_length", "query_length",
    "dot_count", "hyphen_count", "underscore_count", "slash_count",
    "question_count", "equal_count", "at_count", "ampersand_count",
    "percent_count", "hash_count", "digit_count", "host_digit_count",
    "path_digit_count", "digit_ratio", "host_dot_count", "subdomain_count",
    "path_slash_count", "has_double_slash", "has_parent_dir", "query_params_count",
    "has_ip", "risky_tld", "shortener", "url_entropy", "host_entropy",
    "max_char_repeat", "special_char_ratio", "vowel_ratio", "trusted_tld",
    "host_hyphen_count", "host_word_count", "max_word_length",
    "result",
]
