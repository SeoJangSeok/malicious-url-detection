from datetime import datetime
from dns import resolver
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

import whois
import ipaddress
import tldextract
import requests

# =========================================================
# Constants
# =========================================================

HTTP_REQUEST_TIMEOUT_SECONDS = 5


# =========================================================
# Helper Functions
# =========================================================

def normalize_url(raw_url):
    '''
    URL 처리 및 HTTP 요청을 위한 전처리

    - 입력된 URL에 scheme이 없는 경우 'https://'를 추가해준다.
    - 이는 scheme이 없는 경우 urlparse()가 hostname, path 등을 정상적으로
    구분하지 못하는 경우가 있으므로 정상적인 구분을 위해 임시로 추가한다.
    '''
    raw_url = raw_url.strip()

    if not raw_url.lower().startswith(('http://', 'https://')):
        return "https://" + raw_url

    return raw_url


def is_ip_address(hostname):
    '''
    hostname이 IP 주소 형식인지 확인한다.

    반환값
    - IP 주소이면 -> 1
    - 그렇지 않으면 -> 0
    '''
    try:
        ipaddress.ip_address(hostname)
        return 1
    
    except ValueError:
        return 0


def get_registered_domain(hostname):
    '''
    hostname에서 등록 도메인을 추출한다.

    예시
    - www.example.com -> example.com
    - login.shop.example.co.kr -> example.co.kr

    정상적인 등록 도메인을 구할 수 없으면 None을 반환.
    '''
    extracted = tldextract.extract(hostname)

    if not extracted.domain or not extracted.suffix:
        return None

    return f'{extracted.domain}.{extracted.suffix}'


# =========================================================
# WHOIS Features
# =========================================================

def extract_whois_features(hostname):
    '''
    WHOIS 정보를 이용해 도메인 관련 특징값을 추출한다.

    반환 Feature
    - domain_age_days:
        도메인이 생성된 후 현재까지 지난 일수
    
    - registration_period_days:
        도메인의 생성일부터 만료일까지의 등록 기간

    반환값 규칙
    - 숫자: 정상적으로 계산된 Feature 값
    - -1: hostname이 IP 주소라 WHOIS Feature 적용 불가
    - None: WHOIS 조회 실패 또는 정보 미공개
    '''
    features: dict[str, int | None] = {
        'domain_age_days': None,
        'registration_period_days': None
    }

    # IP 주소에는 도메인 WHOIS Feature를 적용할 수 없음
    if is_ip_address(hostname):
        return {'domain_age_days': -1, 'registration_period_days': -1}


    # WHOIS는 subdomain이 아닌 실제 등록 도메인을 기준으로 조회하므로
    # hostname에서 domain + public suffix를 추출한다.
    registered_domain = get_registered_domain(hostname)

    # 등록 도메인을 구할 수 없는 경우
    if registered_domain is None:
        return features

    try:
        domain_info = whois.whois(registered_domain)

        creation_date = domain_info.get('creation_date')
        expiration_date = domain_info.get('expiration_date')

        # creation_date가 여러 개일 경우 가장 오래된 날짜 사용
        if isinstance(creation_date, list):
            valid_creation_dates = [date for date in creation_date if date is not None]
            creation_date = (min(valid_creation_dates) if valid_creation_dates else None)

        # expiration_date가 여러 개일 경우 가장 이후의 날짜 사용
        if isinstance(expiration_date, list):
            valid_expiration_dates = [date for date in expiration_date if date is not None]
            expiration_date = (max(valid_expiration_dates) if valid_expiration_dates else None)

        # 도메인 생성 후 현재까지 지난 일수
        if creation_date is not None:
            now = datetime.now(creation_date.tzinfo)

            features['domain_age_days'] = (now - creation_date).days

        # 최초 생성일부터 현재 등록 만료일까지의 기간      
        if creation_date is not None and expiration_date is not None:
            features['registration_period_days'] = (expiration_date - creation_date).days

    except Exception:
        pass

    return features


# =========================================================
# DNS Features
# =========================================================

def extract_dns_features(hostname):
    '''
    DNS 정보를 이용해 hostname 관련 특징값을 추출한다.

    반환 Feature
    - dns_a_exists:
        hostname의 A 레코드 존재 여부

    - resolved_ip_count:
        hostname이 몇 개의 IPv4 주소로 해석되는지 개수

    - dns_mx_exists:
        registered domain의 MX 레코드 존재 여부

    - dns_ns_count:
        registered domain의 NS 레코드 개수

    반환값 규칙
    - -1: hostname이 IP 주소라 DNS Feature 적용 불가
    - None: DNS 조회 실패

    dns_a_exists / dns_mx_exists
    - 1: 레코드 존재
    - 0: 레코드가 없거나 도메인이 존재하지 않음

    resolved_ip_count / dns_ns_count
    - 0 이상: 조회된 레코드 개수
    '''
    features: dict[str, int | None] = {
        'dns_a_exists': None,
        'resolved_ip_count': None,
        'dns_mx_exists': None,
        'dns_ns_count': None
    }

    # hostname 자체가 IP 주소라면 DNS 이름 해석이 필요하지 않음
    if is_ip_address(hostname):
        return {
            'dns_a_exists': -1,
            'resolved_ip_count': -1,
            'dns_mx_exists': -1,
            'dns_ns_count': -1
        }

    try:
        # hostname의 A 레코드(IPv4 주소)를 조회
        a_answers = resolver.resolve(hostname, 'A')

        features['dns_a_exists'] = 1
        features['resolved_ip_count'] = len(a_answers)

    except (resolver.NoAnswer, resolver.NXDOMAIN):
        features['dns_a_exists'] = 0
        features['resolved_ip_count'] = 0

    except Exception:
        features['dns_a_exists'] = None
        features['resolved_ip_count'] = None

    # MX / NS 조회를 위해 registered domain 추출
    registered_domain = get_registered_domain(hostname)

    if registered_domain is None:
        return features

    # MX Record
    try:
        resolver.resolve(registered_domain, 'MX')
        features['dns_mx_exists'] = 1

    except (resolver.NoAnswer, resolver.NXDOMAIN):
        features['dns_mx_exists'] = 0

    except Exception:
        features['dns_mx_exists'] = None

    # NS Record
    try:
        ns_answers = resolver.resolve(registered_domain, 'NS')
        features['dns_ns_count'] = len(ns_answers)

    except (resolver.NoAnswer, resolver.NXDOMAIN):
        features['dns_ns_count'] = 0

    except Exception:
        features['dns_ns_count'] = None

    return features


# =========================================================
# HTTP Features
# =========================================================

def extract_http_features(url):
    '''
    HTTP 요청을 이용해 URL 관련 특징값을 추출한다.

    반환 Feature
    - redirect_count:
        최종 페이지까지 발생한 redirect 횟수

    - favicon_exists:
        favicon 존재 여부

    - favicon_external_domain:
        favicon이 페이지와 다른 registered domain에 존재하는지 여부

    반환값 규칙
    - redirect_count 반환값
        - 0 이상: redirect 횟수
        - None: HTTP 요청 실패

    - favicon_exists
        - 1: favicon 존재
        - 0: favicon 없음
        - None: 확인 불가

    - favicon_external_domain 반환값
        - 0: favicon이 페이지와 같은 registered domain에 존재
        - 1: favicon이 다른 registered domain에 존재
        - None: favicon 또는 domain 정보를 확인할 수 없음

    주의: 입력 URL에는 http:// 또는 https:// scheme이 포함되어 있어야 한다.
    '''
    features: dict[str, int | None] = {
        'redirect_count': None,
        'favicon_exists': None,
        'favicon_external_domain': None
    }

    try:
        response = requests.get(
            url,
            timeout=HTTP_REQUEST_TIMEOUT_SECONDS,
            allow_redirects=True
        )

        # Redirect 횟수
        features['redirect_count'] = len(response.history)

        # HTML 문서가 아니라면 favicon 분석 불가
        content_type = response.headers.get('Content-Type', '')

        if 'text/html' not in content_type.lower():
            return features

        soup = BeautifulSoup(response.text, 'html.parser')

        favicon_href = None

        # favicon 관련 <link> 태그 탐색
        for link in soup.find_all('link'):
            rel = link.get('rel')

            if rel and 'icon' in rel:
                href = link.get('href')

                if isinstance(href, str) and href.strip():
                    favicon_href = href.strip()
                    break

        # favicon 태그가 존재하는 경우
        if favicon_href is not None:
            favicon_url = urljoin(response.url, favicon_href)

        # favicon 태그가 없으면 기본 위치 /favicon.ico 확인
        else:
            favicon_url = urljoin(response.url, '/favicon.ico')

        # 실제 favicon 존재 여부 확인
        try:
            favicon_response = requests.get(
                favicon_url,
                timeout=HTTP_REQUEST_TIMEOUT_SECONDS,
                allow_redirects=True
            )

            favicon_content_type = favicon_response.headers.get('Content-Type', '')

            if favicon_response.ok and 'image/' in favicon_content_type.lower():
                features['favicon_exists'] = 1

            else:
                features['favicon_exists'] = 0
                return features

        except Exception:
            return features

        # 페이지와 favicon의 hostname 추출
        page_hostname = urlparse(response.url).hostname or ''

        favicon_hostname = urlparse(favicon_response.url).hostname or ''

        # registered domain 추출
        page_domain = get_registered_domain(page_hostname)

        favicon_domain = get_registered_domain(favicon_hostname)

        if page_domain is None or favicon_domain is None:
            return features

        features['favicon_external_domain'] = int(page_domain != favicon_domain)

    except Exception:
        pass

    return features


def extract_host_network_features(url):
    '''
    URL에서 Host / Network Feature를 통합 추출한다.

    반환 Feature
    WHOIS
    - domain_age_days
    - registration_period_days

    DNS
    - dns_a_exists
    - resolved_ip_count
    - dns_mx_exists
    - dns_ns_count

    HTTP
    - redirect_count
    - favicon_exists
    - favicon_external_domain

    주의
    - HTTP Feature 추출 과정에서 실제 URL에 요청을 보낸다.
    - 신뢰할 수 없는 악성 URL에는 직접 사용하지 않는다.
    '''

    normalized_url = normalize_url(url)

    parsed = urlparse(normalized_url)
    hostname = parsed.hostname or ''

    features = {}

    features.update(extract_whois_features(hostname))
    features.update(extract_dns_features(hostname))
    features.update(extract_http_features(normalized_url))

    return features