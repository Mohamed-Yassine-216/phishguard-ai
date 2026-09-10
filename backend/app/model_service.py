from pathlib import Path

import joblib
import pandas as pd
from scipy.sparse import csr_matrix, hstack

from app.features import extract_dataset_features


BASE_DIR = Path(__file__).resolve().parents[1]
MODEL_PATH = BASE_DIR / "ml" / "phishing_model.joblib"

MODEL_BUNDLE = joblib.load(MODEL_PATH)

MODEL = MODEL_BUNDLE["model"]
VECTORIZER = MODEL_BUNDLE["vectorizer"]
IMPUTER = MODEL_BUNDLE["imputer"]
SCALER = MODEL_BUNDLE["scaler"]


def predict_url(url: str) -> dict:
    # Extract the exact same numeric features used during training.
    features = extract_dataset_features(url)

    numeric_df = pd.DataFrame([features])

    # Keep exactly the training feature order.
    numeric_df = numeric_df[
        MODEL_BUNDLE["numeric_features"]
    ]

    # Apply the same preprocessing used during training.
    numeric_values = IMPUTER.transform(numeric_df)
    numeric_values = SCALER.transform(numeric_values)

    # Apply the same TF-IDF vectorizer used during training.
    tfidf_values = VECTORIZER.transform([url])

    # Combine both feature sets.
    final_features = hstack(
        [
            tfidf_values,
            csr_matrix(numeric_values),
        ]
    ).tocsr()

    prediction = int(
        MODEL.predict(final_features)[0]
    )

    phishing_probability = float(
        MODEL.predict_proba(final_features)[0][1]
    )

    risk_score = round(
        phishing_probability * 100,
        2,
    )

    if risk_score >= 80:
        risk_level = "HIGH"
    elif risk_score >= 50:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"


    indicators = []

    if features["has_ip_address"]:
        indicators.append("IP address used instead of a domain")

    if features["https_flag"] == 0:
        indicators.append("Connection does not use HTTPS")

    if features["subdomain_count"] >= 3:
        indicators.append("Large number of subdomains")

    if features["number_of_digits"] >= 5:
        indicators.append("High number of digits in URL")

    if features["percentage_numeric_chars"] >= 20:
        indicators.append("High percentage of numeric characters")

    if features["has_hyphen_in_domain"]:
        indicators.append("Hyphen detected in domain")

    if features["suspicious_file_extension"]:
        indicators.append("Suspicious file extension detected")

    if features["url_length"] >= 100:
        indicators.append("Unusually long URL")

    if features["has_port"]:
        indicators.append("Non-standard port detected")

    if features["has_encoded_characters"]:
        indicators.append("Encoded characters detected")

    if features["has_at_symbol"]:
        indicators.append("@ symbol detected in URL")

    if features["has_double_slash_in_path"]:
        indicators.append("Double slash detected in URL path")

    if features["suspicious_keyword_count"] > 0:
        indicators.append(
            f"Suspicious security-related keywords detected "
            f"({features['suspicious_keyword_count']})"
        )

    if features["is_shortener_domain"]:
        indicators.append("Known URL shortening service detected")

    label = (
        "PHISHING"
        if prediction == 1
        else "LEGITIMATE"
    )

    return {
        "url": url,
        "label": label,
        "phishing_probability": round(
            phishing_probability,
            4,
        ),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicators": indicators,
        "features": features,
    }