from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import joblib
import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from app.features import extract_dataset_features


# ================================================================
# Paths
# ================================================================

BASE_DIR = Path(__file__).resolve().parents[1]

DATA_PATH = BASE_DIR / "data" / "processed" / "phishing_urls_clean.csv"
MODEL_PATH = BASE_DIR / "ml" / "phishing_model.joblib"
METRICS_PATH = BASE_DIR / "ml" / "metrics.json"


# ================================================================
# Configuration
# ================================================================

RANDOM_STATE = 42
TEST_SIZE = 0.20

NUMERIC_FEATURES = [
    "url_length",
    "has_ip_address",
    "dot_count",
    "https_flag",
    "url_entropy",
    "token_count",
    "subdomain_count",
    "query_param_count",
    "tld_length",
    "path_length",
    "has_hyphen_in_domain",
    "number_of_digits",
    "suspicious_file_extension",
    "domain_name_length",
    "percentage_numeric_chars",

    # New features
    "domain_entropy",
    "path_segment_count",
    "has_port",
    "has_encoded_characters",
    "has_at_symbol",
    "has_double_slash_in_path",
    "suspicious_keyword_count",
    "has_suspicious_keyword",
    "is_shortener_domain",
]


# ================================================================
# Load dataset
# ================================================================

print("=" * 70)
print("PHISHGUARD AI - MODEL TRAINING")
print("=" * 70)

print("\nLoading dataset...")

df = pd.read_csv(DATA_PATH)

df = df.dropna(subset=["URL", "ClassLabel"]).copy()

df["URL"] = df["URL"].astype(str).str.strip()

df = df[df["URL"] != ""].copy()

df = df.drop_duplicates(subset=["URL"]).reset_index(drop=True)

print(f"Dataset: {len(df):,} URLs")


# ================================================================
# Convert labels
# ================================================================

# Dataset:
# ClassLabel 0 = phishing
# ClassLabel 1 = legitimate
#
# Application:
# label 0 = legitimate
# label 1 = phishing

df["label"] = 1 - df["ClassLabel"].astype(int)

print("\nClass distribution:")
print(
    df["label"]
    .value_counts()
    .sort_index()
    .rename(
        index={
            0: "Legitimate",
            1: "Phishing",
        }
    )
)


# ================================================================
# Train/test split
# ================================================================

X_train_urls, X_test_urls, y_train, y_test = train_test_split(
    df["URL"],
    df["label"],
    test_size=TEST_SIZE,
    random_state=RANDOM_STATE,
    stratify=df["label"],
)

print("\nSplit:")
print(f"Training: {len(X_train_urls):,}")
print(f"Testing : {len(X_test_urls):,}")


# ================================================================
# Extract numeric URL features
# ================================================================

print("\nExtracting URL features...")

train_numeric = pd.DataFrame(
    [
        extract_dataset_features(url)
        for url in X_train_urls
    ]
)

test_numeric = pd.DataFrame(
    [
        extract_dataset_features(url)
        for url in X_test_urls
    ]
)

train_numeric = train_numeric[NUMERIC_FEATURES]
test_numeric = test_numeric[NUMERIC_FEATURES]


# ================================================================
# Imputation + scaling
# ================================================================

imputer = SimpleImputer(strategy="median")

train_numeric = imputer.fit_transform(train_numeric)
test_numeric = imputer.transform(test_numeric)

scaler = StandardScaler()

train_numeric = scaler.fit_transform(train_numeric)
test_numeric = scaler.transform(test_numeric)


# ================================================================
# Character TF-IDF
# ================================================================

print("\nBuilding character TF-IDF...")

vectorizer = TfidfVectorizer(
    analyzer="char",
    ngram_range=(3, 5),
    min_df=2,
    max_features=30000,
    sublinear_tf=True,
)

train_tfidf = vectorizer.fit_transform(X_train_urls)

test_tfidf = vectorizer.transform(X_test_urls)

print(f"TF-IDF features: {train_tfidf.shape[1]:,}")


# ================================================================
# Combine features
# ================================================================

train_features = hstack(
    [
        train_tfidf,
        csr_matrix(train_numeric),
    ]
).tocsr()

test_features = hstack(
    [
        test_tfidf,
        csr_matrix(test_numeric),
    ]
).tocsr()

print(
    f"Final training matrix: {train_features.shape}"
)

print(
    f"Final testing matrix : {test_features.shape}"
)


# ================================================================
# Train model
# ================================================================

print("\nTraining Logistic Regression...")

model = LogisticRegression(
    max_iter=1000,
    class_weight="balanced",
    random_state=RANDOM_STATE,
)

model.fit(train_features, y_train)


# ================================================================
# Evaluation
# ================================================================

y_pred = model.predict(test_features)

y_probability = model.predict_proba(
    test_features
)[:, 1]


accuracy = accuracy_score(
    y_test,
    y_pred,
)

precision = precision_score(
    y_test,
    y_pred,
    zero_division=0,
)

recall = recall_score(
    y_test,
    y_pred,
    zero_division=0,
)

f1 = f1_score(
    y_test,
    y_pred,
    zero_division=0,
)

roc_auc = roc_auc_score(
    y_test,
    y_probability,
)

cm = confusion_matrix(
    y_test,
    y_pred,
)


# ================================================================
# Print results
# ================================================================

print("\n")
print("=" * 70)
print("MODEL PERFORMANCE")
print("=" * 70)

print(f"Accuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1 Score : {f1:.4f}")
print(f"ROC-AUC  : {roc_auc:.4f}")

print("\nConfusion Matrix:")
print(cm)

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        y_pred,
        target_names=[
            "Legitimate",
            "Phishing",
        ],
        zero_division=0,
    )
)


# ================================================================
# Save model bundle
# ================================================================

model_bundle = {
    "model": model,
    "vectorizer": vectorizer,
    "imputer": imputer,
    "scaler": scaler,
    "numeric_features": NUMERIC_FEATURES,
}

joblib.dump(
    model_bundle,
    MODEL_PATH,
)


# ================================================================
# Save metrics
# ================================================================

metrics = {
    "accuracy": float(accuracy),
    "precision": float(precision),
    "recall": float(recall),
    "f1_score": float(f1),
    "roc_auc": float(roc_auc),
    "training_samples": int(len(X_train_urls)),
    "testing_samples": int(len(X_test_urls)),
    "tfidf_features": int(train_tfidf.shape[1]),
    "numeric_features": len(NUMERIC_FEATURES),
}


import json

with open(
    METRICS_PATH,
    "w",
    encoding="utf-8",
) as file:
    json.dump(
        metrics,
        file,
        indent=4,
    )


print("\nModel saved:")
print(MODEL_PATH)

print("\nMetrics saved:")
print(METRICS_PATH)

print("\nTraining completed successfully.")