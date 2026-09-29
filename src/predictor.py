from pathlib import Path

import joblib
import pandas as pd

from host_network_feature_extractor import extract_host_network_features
from lexical_feature_extractor import extract_lexical_features

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
    features = extract_features(url)

    # 모델별 Feature 구성
    rf_input = pd.DataFrame(
        [[features[feature] for feature in rf_features]], columns=rf_features
    )

    iso_input = pd.DataFrame(
        [[features[feature] for feature in iso_features]], columns=iso_features
    )

    # 결츨치 처리
    rf_input_imputed = rf_imputer.transform(rf_input)
    iso_input_imputed = iso_imputer.transform(iso_input)

    # Random Forest
    rf_probability = rf_model.predict_proba(rf_input_imputed)[0, 1]
    rf_prediction = int(rf_probability >= rf_threshold)

    # Isolation Forest
    iso_anomaly_score = -iso_model.decision_function(iso_input_imputed)[0]
    iso_prediction = int(iso_anomaly_score >= iso_threshold)

    final_prediction = "MALICIOUS" if rf_prediction == 1 else "NORMAL"

    return {
        "url": url,
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
    test_url = "https://www.google.com/"

    result = predict_url(test_url)

    print("URL:", result["url"])
    print("RF 악성 확률:", result["rf_probability"])
    print("RF 판정:", result["rf_prediction"])
    print("IF 이상 점수:", result["iso_anomaly_score"])
    print("IF 판정:", result["iso_prediction"])
    print("최종 판정:", result["final_prediction"])
if __name__ == "__main__":
    test_url = "https://paypal3.vercel.app/"

    result = predict_url(test_url)

    print("URL:", result["url"])
    print("RF 악성 확률:", result["rf_probability"])
    print("RF 판정:", result["rf_prediction"])
    print("IF 이상 점수:", result["iso_anomaly_score"])
    print("IF 판정:", result["iso_prediction"])
    print("최종 판정:", result["final_prediction"])
