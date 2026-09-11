from urllib.parse import urlparse
from collections import Counter
import math
import ipaddress
import tldextract

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


def normalize_url(raw_url):
    '''
    URL parsing을 위한 전처리

    - 입력된 URL에 scheme이 없는 경우 'https://'를 추가해준다.
    - 이는 scheme이 없는 경우 urlparse()가 hostname, path 등을 정상적으로
    구분하지 못하는 경우가 있으므로 정상적인 구분을 위해 임시로 추가한다.
    '''
    raw_url = raw_url.strip()

    if not raw_url.lower().startswith(('http://', 'https://')):
        return "https://" + raw_url

    return raw_url


def calculate_shannon_entropy(text):
    '''
    문자열의 Shannon entropy를 계산한다.

    - 문자열에 포함된 각 문자의 출현 확률을 계산한다.
    - 문자 분포가 다양하고 불규칙할수록 entropy 값이 높아진다.
    - 빈 문자열이 입력되면 0.0을 반환한다.
    '''
    # 빈 문자열인 경우 entropy는 0
    if not text:
        return 0.0

    text_length = len(text)
    char_counts = Counter(text)

    entropy = 0.0

    for count in char_counts.values():
        probability = count / text_length

        # Shannon entropy 공식: -Σ p(x) log2 p(x)
        entropy -= probability * math.log2(probability)

    return entropy


def is_ip_address(hostname):
    '''
    hostname이 IP 주소 형식인지 확인한다.

    - IP 주소이면 -> 1
    - 그렇지 않으면 -> 0
    '''
    try:
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0


# 단축 URL 여부 확인
def is_shortened_url(hostname):
    '''
    입력된 hostname이 단축 URL 서비스 도메인인지 확인한다.

    SHORTENER_DOMAINS 목록과 비교하여
    - 단축 URL이면 -> 1
    - 그렇지 않으면 -> 0
    '''
    hostname = hostname.lower()

    if hostname.startswith('www.'):
        hostname = hostname[4:]

    return int(hostname in SHORTENER_DOMAINS)


# 의심스러운 키워드 개수 확인
def count_suspicious_keywords(raw_url):
    '''
    URL 전체에 포함된 의심스러운 키워드의 종류 수를 계산한다.

    SUSPICIOUS_KEYWORDS 목록의 각 키워드가 URL에 있으면 +1
    동일한 키워드가 여러 번 등장해도 1개로 계산한다.
    '''
    raw_url = raw_url.lower()

    return sum(keyword in raw_url for keyword in SUSPICIOUS_KEYWORDS)

# URL의 주요 구성 요소에 대한 길이 측정
def extract_length_features(raw_url, hostname, path, query):
    '''
    URL의 주요 구성 요소에 대한 길이 특징을 계산한다.
    '''
    return {
        'url_length': len(raw_url),
        'hostname_length': len(hostname),
        'path_length': len(path),
        'query_length': len(query)
    }

# URL의 구조적 복잡도 특징
def extract_structure_features(hostname, path):
    '''
    URL의 구조와 관련된 특징값을 계산한다.

    - subdomain_count: 
        hostname에 포함된 subdomain의 개수를 계산한다.
        IP 주소인 경우 subdomain은 0으로 처리한다.
    - path_depth: path를 '/' 기준으로 나누어 실제 경로 단계를 확인한다.
    '''
    # Subdomain 개수
    if is_ip_address(hostname):
        subdomain_count = 0

    else:    
        extracted = tldextract.extract(hostname)

        subdomain_count = (len(extracted.subdomain.split('.')) if extracted.subdomain else 0)

    # Path 깊이
    path_segments = [segment for segment in path.split('/') if segment]
    path_depth = len(path_segments)

    return {
        'subdomain_count': subdomain_count,
        'path_depth': path_depth
    }


def extract_format_features(raw_url, parsed, hostname):
    '''
    URL의 형식과 관련된 특징값을 계산한다.

    - has_ip_address: hostname이 도메인 이름이 아닌 IP 주소 형식인지 확인한다.

    - is_https: URL의 scheme이 https인지 확인한다.

    - has_https_token_in_hostname: hostname 문자열 내부에 'https'라는 문자열이 포함되어 있는지 확인한다.

    - has_punycode: hostname에 Punycode 표현인 'xn--'가 포함되어 있는지 확인한다.

    - has_nonstandard_port: URL에 (80, 443)이 아닌 포트가 명시되어 있는지 확인한다.
    '''
    # 잘못된 포트 형식이 입력될 경우 ValueError가 발생
    try:
        port = parsed.port
        has_nonstandard_port = int(port is not None and port not in (80, 443))
    except ValueError:
        has_nonstandard_port = 1

    return {
        'has_ip_address': is_ip_address(hostname),
        'is_https': int(raw_url.lower().startswith('https://')),
        'has_https_token_in_hostname': int('https' in hostname.lower()),
        'is_shortened_url': is_shortened_url(hostname),
        'has_punycode': int('xn--' in hostname.lower()),
        'has_nonstandard_port': has_nonstandard_port
    }

def extract_numeric_features(raw_url, hostname):
    '''
    URL과 hostname에 포함된 숫자 관련 특징값을 계산한다.

    - digit_count: 전체 URL에 포함된 숫자의 개수.
    - digit_ratio: 전체 URL 길이에서 숫자가 차지하는 비율.
    - hostname_digit_count: hostname에 포함된 숫자의 개수.
    - hostname_digit_ratio: hostname 길이에서 숫자가 차지하는 비율.
    '''
    # 전체 URL의 숫자 개수
    digit_count = sum(char.isdigit() for char in raw_url)

    # hostname의 숫자 개수
    hostname_digit_count = sum(char.isdigit() for char in hostname)

    return {
        'digit_count': digit_count,
        'digit_ratio': (digit_count / len(raw_url) if raw_url else 0.0),
        'hostname_digit_count': hostname_digit_count,
        'hostname_digit_ratio': (hostname_digit_count / len(hostname) if hostname else 0.0)
    }

# 특수문자 관련 특징
def extract_special_character_features(raw_url, hostname):
    '''
    URL과 hostname에 포함된 특수문자 관련 특징값을 계산한다.

    - special_char_count: 전체 URL에 포함된 영문자/숫자가 아닌 문자의 개수
    - special_char_ratio: 전체 URL 길이에서 특수문자가 차지하는 비율
    - 각 특수문자의 등장 횟수를 각각 계산
    - hostname_hyphen_count: hostname에 포함된 '-' 문자의 개수
    '''
    special_char_count = sum(not char.isalnum() for char in raw_url)

    return {
        'special_char_count': special_char_count,
        'special_char_ratio': (special_char_count / len(raw_url) if raw_url else 0.0),

        "dot_count": raw_url.count("."),
        "hyphen_count": raw_url.count("-"),
        "underscore_count": raw_url.count("_"),
        "slash_count": raw_url.count("/"),
        "at_count": raw_url.count("@"),
        "question_count": raw_url.count("?"),
        "equal_count": raw_url.count("="),
        "ampersand_count": raw_url.count("&"),
        "percent_count": raw_url.count("%"),

        'hostname_hyphen_count': hostname.count('-')
    }

# Shannon entropy 값 계산
def extract_entropy_features(raw_url, hostname):
    '''
    URL과 hostname의 Shannon entropy를 계산한다.

    - url_entropy: 전체 URL 문자열의 entropy
    - hostname_entropy: hostname 문자열의 entropy

    문자열 내 문자 분포가 다양하고 불규칙할수록 entropy 값이 높아진다.
    '''
    return {
        'url_entropy': calculate_shannon_entropy(raw_url),
        'hostname_entropy': calculate_shannon_entropy(hostname)
    }

# =========================================================
# Lexical Feature Extractor
# =========================================================
def extract_lexical_features(url):
    raw_url = url.strip()

    normalized_url = normalize_url(raw_url)
    parsed = urlparse(normalized_url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    features = {}

    features.update(extract_length_features(raw_url, hostname, path, query))
    features.update(extract_structure_features(hostname, path))
    features.update(extract_format_features(raw_url, parsed, hostname))
    features.update(extract_numeric_features(raw_url, hostname))
    features.update(extract_special_character_features(raw_url, hostname))
    features["suspicious_keyword_count"] = (count_suspicious_keywords(raw_url))
    features.update(extract_entropy_features(raw_url, hostname))

    return features