from urllib.parse import urlparse
import ipaddress
import math

import tldextract


# =========================================================
# Constants
# =========================================================

# 단축 URL 서비스 목록
SHORTENER_DOMAINS = {
    "bit.ly",
    "buff.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "rb.gy",
    "rebrand.ly",
    "shorturl.at",
    "t.co",
    "tiny.cc",
    "tinyurl.com",
    "trib.al",
    "v.gd",
    "youtu.be",
}

# 의심스러운 키워드 목록
SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "secure",
    "account",
    "update",
    "confirm",
    "password",
}


# =========================================================
# Helper Functions
# =========================================================

def normalize_url(url):
    """
    URL에 scheme이 없는 경우 https://를 추가한다.
    """
    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


def calculate_entropy(text):
    """
    문자열의 Shannon entropy를 계산한다.
    """
    if not text:
        return 0.0

    entropy = 0.0
    text_length = len(text)

    for char in set(text):
        probability = text.count(char) / text_length
        entropy -= probability * math.log2(probability)

    return entropy


# =========================================================
# Lexical Feature Extractor
# =========================================================

def extract_lexical_features(url):
    """
    URL에서 31개의 lexical feature를 추출하여 dictionary로 반환한다.

    Feature categories:
    - Length / Structure
    - Format
    - Numeric
    - Special Character
    - Suspicious Keyword
    - Entropy
    """

    url = normalize_url(url)
    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    features = {}

    # =====================================================
    # 1. URL Length / Structure Features
    # =====================================================

    features["url_length"] = len(url)
    features["hostname_length"] = len(hostname)
    features["path_length"] = len(path)
    features["query_length"] = len(query)

    # IP address 여부
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    # Subdomain 개수
    if is_ip:
        features["subdomain_count"] = 0
    else:
        extracted = tldextract.extract(hostname)

        features["subdomain_count"] = (
            len(extracted.subdomain.split("."))
            if extracted.subdomain
            else 0
        )

    # Path 깊이
    path_segments = [
        segment
        for segment in path.split("/")
        if segment
    ]

    features["path_depth"] = len(path_segments)

    # =====================================================
    # 2. Format Features
    # =====================================================

    features["has_ip_address"] = 1 if is_ip else 0

    features["is_https"] = (
        1 if parsed.scheme.lower() == "https" else 0
    )

    features["has_https_token_in_hostname"] = (
        1 if "https" in hostname.lower() else 0
    )

    # URL Shortener
    normalized_hostname = hostname.lower()

    if normalized_hostname.startswith("www."):
        normalized_hostname = normalized_hostname[4:]

    features["is_shortened_url"] = (
        1 if normalized_hostname in SHORTENER_DOMAINS else 0
    )

    # Punycode
    features["has_punycode"] = (
        1 if "xn--" in hostname.lower() else 0
    )

    # Non-standard Port
    try:
        port = parsed.port
    except ValueError:
        port = None

    features["has_nonstandard_port"] = (
        1 if port is not None and port not in (80, 443) else 0
    )

    # =====================================================
    # 3. Numeric Features
    # =====================================================

    digit_count = sum(
        char.isdigit()
        for char in url
    )

    features["digit_count"] = digit_count

    features["digit_ratio"] = (
        digit_count / len(url)
        if url
        else 0.0
    )

    domain_digit_count = sum(
        char.isdigit()
        for char in hostname
    )

    features["domain_digit_count"] = domain_digit_count

    features["domain_digit_ratio"] = (
        domain_digit_count / len(hostname)
        if hostname
        else 0.0
    )

    # =====================================================
    # 4. Special Character Features
    # =====================================================

    special_char_count = sum(
        not char.isalnum()
        for char in url
    )

    features["special_char_count"] = special_char_count

    features["special_char_ratio"] = (
        special_char_count / len(url)
        if url
        else 0.0
    )

    features["dot_count"] = url.count(".")
    features["hyphen_count"] = url.count("-")
    features["underscore_count"] = url.count("_")
    features["slash_count"] = url.count("/")
    features["at_count"] = url.count("@")
    features["question_count"] = url.count("?")
    features["equal_count"] = url.count("=")
    features["ampersand_count"] = url.count("&")
    features["percent_count"] = url.count("%")
    features["hyphen_count_domain"] = hostname.count("-")

    # =====================================================
    # 5. Suspicious Keyword Feature
    # =====================================================

    url_lower = url.lower()

    features["suspicious_keyword_count"] = sum(
        keyword in url_lower
        for keyword in SUSPICIOUS_KEYWORDS
    )

    # =====================================================
    # 6. Entropy Features
    # =====================================================

    features["url_entropy"] = calculate_entropy(url)
    features["domain_entropy"] = calculate_entropy(hostname)

    return features