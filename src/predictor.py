import ipaddress
from pathlib import Path
from urllib.parse import urlparse

import joblib
import pandas as pd

from host_network_feature_extractor import extract_host_network_features
from lexical_feature_extractor import extract_lexical_features

# RFC1918에서 정의한 사설 IPv4 주소 범위
# 일반적으로 가정, 학교, 회사 등의 내부 네트워크에서 사용된다
RFC1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

# 통신사가 여러 가입자에게 하나의 공인 IP를 공유하기 위해
# 사용하는 Carrier-Grade NAT(CGNAT) 주소 범위
CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")


def is_rfc1918_private(ip):
    """
    입력된 IP 주소가 RFC1918에서 정의한
    사설 IPv4 주소 범위에 포함되는지 확인한다.

    Parameters
    ----------
    ip : ipaddress.IPv4Address
        확인할 IP 주소 객체

    Returns
    -------
    bool
        RFC1918 사설 주소이면 True,
        아니면 False
    """

    # RFC1918_NETWORKS에 정의된 각 네트워크 범위를 확인한다.
    # 하나라도 포함되어 있으면 True를 반환한다.
    return any(ip in network for network in RFC1918_NETWORKS)


def classify_url_host(url):
    """
    URL의 hostname을 추출한 뒤
    도메인인지 IP 주소인지 확인하고,
    IP 주소라면 사용 목적에 따라 종류를 분류한다.

    모델 학습 데이터에는 DOMAIN과 PUBLIC IP만 존재하므로
    두 종류만 기존 RF + IF 모델의 검사 대상으로 사용한다.

    Parameters
    ----------
    url : str
        검사할 URL

    Returns
    -------
    str
        다음 중 하나의 문자열을 반환한다.

        IPv6_UNSUPPORTED
            현재 모델에서 지원하지 않는 IPv6 주소인 경우

        INVALID
            hostname을 정상적으로 추출할 수 없는 경우

        DOMAIN
            hostname이 IP 주소가 아닌 일반 도메인인 경우

        RFC1918_PRIVATE
            RFC1918에서 정의한 사설 IP인 경우

        LOOPBACK
            자기 자신의 컴퓨터를 가리키는 주소인 경우

        LINK_LOCAL
            동일한 로컬 네트워크 링크에서 사용하는 주소인 경우

        CGNAT
            통신사의 Carrier-Grade NAT 용 주소인 경우

        MULTICAST
            여러 수신자에게 데이터를 전송하기 위한 주소인 경우

        UNSPECIFIED
            특정 IP 주소가 지정되지 않았음을 나타내는 경우

        RESERVED
            일반적인 인터넷 호스트 용도가 아닌
            예약된 특수 IP 주소인 경우

        PUBLIC
            인터넷에서 일반적으로 라우팅 가능한 공인 IP인 경우

        OTHER
            위 분류에 포함되지 않는 기타 특수 IP 주소인 경우
    """

    hostname = urlparse(url).hostname

    if hostname is None:
        return "INVALID"

    try:
        ip = ipaddress.ip_address(hostname)

    except ValueError:
        return "DOMAIN"

    if ip.version == 6:
        return "IPv6_UNSUPPORTED"

    if is_rfc1918_private(ip):
        return "RFC1918_PRIVATE"

    if ip.is_loopback:
        return "LOOPBACK"

    if ip.is_link_local:
        return "LINK_LOCAL"

    if ip in CGNAT_NETWORK:
        return "CGNAT"

    if ip.is_multicast:
        return "MULTICAST"

    if ip.is_unspecified:
        return "UNSPECIFIED"

    if ip.is_reserved:
        return "RESERVED"

    if ip.is_global:
        return "PUBLIC"

    return "OTHER"


# =========================================================
# Model Paths
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

RF_MODEL_PATH = BASE_DIR / "models" / "random_forest_final.joblib"
IF_MODEL_PATH = BASE_DIR / "models" / "isolation_forest_final.joblib"


# =========================================================
# Model Loading
# =========================================================

rf_bundle = joblib.load(RF_MODEL_PATH)
iso_bundle = joblib.load(IF_MODEL_PATH)

rf_model = rf_bundle["model"]
rf_imputer = rf_bundle["imputer"]
rf_threshold = rf_bundle["threshold"]
rf_features = rf_bundle["features"]

iso_model = iso_bundle["model"]
iso_imputer = iso_bundle["imputer"]
iso_threshold = iso_bundle["threshold"]
iso_features = iso_bundle["features"]


# =========================================================
# Feature Extraction
# =========================================================


def extract_features(url):
    lexical_features = extract_lexical_features(url)
    host_features = extract_host_network_features(url)

    return {**lexical_features, **host_features}


# =========================================================
# URL Prediction
# =========================================================


def predict_url(url):
    # URL의 hostname 종류를 확인
    host_type = classify_url_host(url)

    # 현재 모델의 학습 범위에 포함되지 않는 주소는
    # RF / Isolation Forest 모델에 전달하지 않음
    if host_type not in ["DOMAIN", "PUBLIC"]:
        return {
            "url": url,
            "host_type": host_type,
            "rf_probability": None,
            "rf_prediction": None,
            "iso_anomaly_score": None,
            "iso_prediction": None,
            "anomaly_detected": None,
            "final_prediction": "NOT_APPLICABLE",
        }

    # DOMAIN 또는 PUBLIC IP인 경우 기존 모델 예측 진행
    features = extract_features(url)

    # 모델별 Feature 구성
    rf_input = pd.DataFrame(
        [[features[feature] for feature in rf_features]], columns=rf_features
    )

    iso_input = pd.DataFrame(
        [[features[feature] for feature in iso_features]], columns=iso_features
    )

    # 결측치 처리
    rf_input_imputed = rf_imputer.transform(rf_input)
    iso_input_imputed = iso_imputer.transform(iso_input)

    # Random Forest
    rf_probability = rf_model.predict_proba(rf_input_imputed)[0, 1]
    rf_prediction = int(rf_probability >= rf_threshold)

    # Isolation Forest
    iso_anomaly_score = -iso_model.decision_function(iso_input_imputed)[0]
    iso_prediction = int(iso_anomaly_score >= iso_threshold)

    # 최종 정상/악성 판정은 Random Forest가 담당
    final_prediction = "MALICIOUS" if rf_prediction == 1 else "NORMAL"

    return {
        "url": url,
        "host_type": host_type,
        "rf_probability": float(rf_probability),
        "rf_prediction": rf_prediction,
        "iso_anomaly_score": float(iso_anomaly_score),
        "iso_prediction": iso_prediction,
        "anomaly_detected": bool(iso_prediction),
        "final_prediction": final_prediction,
    }


# =========================================================
# Test
# =========================================================

if __name__ == "__main__":
    test_urls = [
        "https://www.google.com/",
        "https://paypal3.vercel.app/",
        "http://103.193.179.78/",
        "http://192.168.0.1/easymesh/",
        "http://127.0.0.1:8000/",
        "http://169.254.1.1/",
        "http://100.64.0.1/",
        "http://224.0.0.1/",
        "http://0.0.0.0/",
    ]

    for test_url in test_urls:
        result = predict_url(test_url)

        print("\n==============================")
        print("URL:", result["url"])
        print("Host 종류:", result["host_type"])
        print("RF 악성 확률:", result["rf_probability"])
        print("RF 판정:", result["rf_prediction"])
        print("IF 이상 점수:", result["iso_anomaly_score"])
        print("IF 판정:", result["iso_prediction"])
        print("최종 판정:", result["final_prediction"])
