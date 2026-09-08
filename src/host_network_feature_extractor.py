from datetime import datetime
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from dns import resolver

import ipaddress
import requests
import whois
import tldextract

REQUEST_TIMEOUT = 5 # seconds

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

def get_registered_domain(hostname):
    """
    hostname에서 등록 도메인(domain + public suffix)을 반환한다.
    """
    extracted = tldextract.extract(hostname)

    if not extracted.domain or not extracted.suffix:
        return None

    return f"{extracted.domain}.{extracted.suffix}"

def is_ip_address(hostname):
    '''
    hostname이 IP 주소인지 확인한다.
    '''
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


# =========================================================
# WHOIS Features
# =========================================================

def extract_whois_features(hostname):
    """
    WHOIS를 이용해 다음 Feature를 추출한다.

    - domain_age_days
    - registration_period_days
    """
    features: dict[str, int | None] = {
        "domain_age_days": None,
        "registration_period_days": None,
    }

    # IP 주소에는 도메인 WHOIS Feature를 적용하지 않음
    if is_ip_address(hostname):
        return features

    registered_domain = get_registered_domain(hostname)

    if registered_domain is None:
        return features

    try:
        domain_info = whois.whois(registered_domain)

        creation_date = domain_info.get("creation_date")
        expiration_date = domain_info.get("expiration_date")

        # creation_date가 여러 개인 경우 가장 오래된 날짜 사용
        if isinstance(creation_date, list):
            valid_creation_dates = [
                date
                for date in creation_date
                if date is not None
            ]

            creation_date = (
                min(valid_creation_dates)
                if valid_creation_dates
                else None
            )

        # expiration_date가 여러 개인 경우 가장 먼 날짜 사용
        if isinstance(expiration_date, list):
            valid_expiration_dates = [
                date
                for date in expiration_date
                if date is not None
            ]

            expiration_date = (
                max(valid_expiration_dates)
                if valid_expiration_dates
                else None
            )

        # Domain Age
        if creation_date is not None:
            now = datetime.now(creation_date.tzinfo)

            features["domain_age_days"] = (
                now - creation_date
            ).days

        # Registration Period
        if (
            creation_date is not None
            and expiration_date is not None
        ):
            features["registration_period_days"] = (
                expiration_date - creation_date
            ).days

    except Exception:
        pass

    return features


# =========================================================
# DNS Features
# =========================================================

def extract_dns_features(hostname):
    """
    DNS를 이용해 다음 Feature를 추출한다.

    - dns_a_exists
    - resolved_ip_count
    - dns_mx_exists
    - dns_ns_count
    """
    features: dict[str, int | None] = {
        "dns_a_exists": None,
        "resolved_ip_count": None,
        "dns_mx_exists": None,
        "dns_ns_count": None,
    }

    # IP 주소에는 DNS Feature를 적용하지 않음
    if is_ip_address(hostname):
        return features

    # -----------------------------------------------------
    # A Record / Resolved IP Count
    # -----------------------------------------------------

    try:
        a_answers = resolver.resolve(hostname, "A")

        features["dns_a_exists"] = 1
        features["resolved_ip_count"] = len(a_answers)

    except (resolver.NoAnswer, resolver.NXDOMAIN):
        features["dns_a_exists"] = 0
        features["resolved_ip_count"] = 0

    except Exception:
        features["dns_a_exists"] = None
        features["resolved_ip_count"] = None

    # -----------------------------------------------------
    # MX Record
    # -----------------------------------------------------

    try:
        resolver.resolve(hostname, "MX")
        features["dns_mx_exists"] = 1

    except (resolver.NoAnswer, resolver.NXDOMAIN):
        features["dns_mx_exists"] = 0

    except Exception:
        features["dns_mx_exists"] = None

    # -----------------------------------------------------
    # NS Record
    # -----------------------------------------------------

    try:
        ns_answers = resolver.resolve(hostname, "NS")
        features["dns_ns_count"] = len(ns_answers)

    except (resolver.NoAnswer, resolver.NXDOMAIN):
        features["dns_ns_count"] = 0

    except Exception:
        features["dns_ns_count"] = None

    return features


# =========================================================
# HTTP Features
# =========================================================

def extract_http_features(url):
    """
    한 번의 HTTP 요청으로 다음 Feature를 추출한다.

    - redirect_count
    - favicon_external_domain
    """
    features: dict[str, int | None] = {
        "redirect_count": None,
        "favicon_external_domain": None,
    }

    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )

        # Redirect Count
        features["redirect_count"] = len(response.history)

        # HTML이 아니면 favicon 분석은 수행하지 않음
        content_type = response.headers.get("Content-Type", "")

        if "text/html" not in content_type.lower():
            return features

        soup = BeautifulSoup(
            response.text,
            "html.parser",
        )

        favicon_href = None

        # favicon 태그 탐색
        for link in soup.find_all("link"):
            rel = link.get("rel")

            if rel and "icon" in rel:
                href = link.get("href")

                if isinstance(href, str):
                    favicon_href = href

                break

        # favicon 태그가 없으면 브라우저 기본 위치 사용
        if favicon_href is None:
            favicon_href = "/favicon.ico"

        favicon_url = urljoin(
            response.url,
            favicon_href,
        )

        page_hostname = (
            urlparse(response.url).hostname or ""
        )

        favicon_hostname = (
            urlparse(favicon_url).hostname or ""
        )

        page_domain = get_registered_domain(
            page_hostname
        )

        favicon_domain = get_registered_domain(
            favicon_hostname
        )

        if (
            page_domain is None
            or favicon_domain is None
        ):
            return features

        features["favicon_external_domain"] = (
            1 if page_domain != favicon_domain else 0
        )

    except Exception:
        pass

    return features


# =========================================================
# Integrated Host / Network Feature Extractor
# =========================================================

def extract_host_network_features(url):
    """
    URL에서 총 8개의 Host / Network Feature를 추출한다.

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
    - favicon_external_domain
    """
    url = normalize_url(url)

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    features = {}

    features.update(
        extract_whois_features(hostname)
    )

    features.update(
        extract_dns_features(hostname)
    )

    features.update(
        extract_http_features(url)
    )

    return features


#---------------------------------------------------------
# HTTP 호출 없이 WHOIS, DNS Feature만 추출하는 함수
#---------------------------------------------------------
def extract_safe_host_network_features(url):
    """
    URL에서 HTTP 요청 없이 안전하게 추출 가능한
    Host / Network Feature 6개를 반환한다.

    WHOIS
    - domain_age_days
    - registration_period_days

    DNS
    - dns_a_exists
    - resolved_ip_count
    - dns_mx_exists
    - dns_ns_count
    """
    url = normalize_url(url)

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    features = {}

    features.update(extract_whois_features(hostname))
    features.update(extract_dns_features(hostname))

    return features