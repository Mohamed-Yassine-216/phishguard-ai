from pathlib import Path
from urllib.parse import urlparse
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import joblib
import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)

from app.features import extract_dataset_features


BASE_DIR = Path(__file__).resolve().parents[1]
DATA_PATH = BASE_DIR / "data" / "processed" / "phishing_urls_clean.csv"
MODEL_PATH = BASE_DIR / "ml" / "phishing_model.joblib"

RANDOM_STATE = 42
TEST_SIZE = 0.20


def get_hostname(url: str) -> str:
    """Return the normalized hostname used for grouping."""
    value = str(url).strip()

    if not value.startswith(("http://", "https://")):
        value = "http://" + value

    try:
        hostname = urlparse(value).hostname
        return hostname.lower().strip(".") if hostname else ""
    except Exception:
        return ""


print("=" * 70)
print("DOMAIN-AWARE PHISHING MODEL EVALUATION")
print("=" * 70)

# -------------------------------------------------------------------
# 1. Load dataset
# -------------------------------------------------------------------

df = pd.read_csv(DATA_PATH)

df = df.dropna(subset=["URL", "ClassLabel"]).copy()
df["URL"] = df["URL"].astype(str).str.strip()

df = df[df["URL"] != ""].copy()
df = df.drop_duplicates(subset=["URL"]).reset_index(drop=True)

# Dataset convention:
# ClassLabel 0 = phishing
# ClassLabel 1 = legitimate
#
# Application convention:
# label 0 = legitimate
# label 1 = phishing
df["label"] = 1 - df["ClassLabel"].astype(int)

# -------------------------------------------------------------------
# 2. Extract hostname groups
# -------------------------------------------------------------------

print(f"\nTotal URLs: {len(df):,}")

df["hostname"] = df["URL"].apply(get_hostname)

invalid_hosts = (df["hostname"] == "").sum()

if invalid_hosts:
    print(f"Removing {invalid_hosts} URLs with invalid hostnames...")
    df = df[df["hostname"] != ""].copy()

print(f"Unique hostnames: {df['hostname'].nunique():,}")

# -------------------------------------------------------------------
# 3. Domain-aware split
# -------------------------------------------------------------------

rng = np.random.RandomState(RANDOM_STATE)

hostnames = df["hostname"].unique()
rng.shuffle(hostnames)

test_host_count = max(1, int(len(hostnames) * TEST_SIZE))

test_hosts = set(hostnames[:test_host_count])

test_df = df[df["hostname"].isin(test_hosts)].copy()
train_df = df[~df["hostname"].isin(test_hosts)].copy()

print("\nDOMAIN-AWARE SPLIT")
print("-" * 70)
print(f"Training URLs : {len(train_df):,}")
print(f"Testing URLs  : {len(test_df):,}")
print(f"Training hosts: {train_df['hostname'].nunique():,}")
print(f"Testing hosts : {test_df['hostname'].nunique():,}")

overlap = set(train_df["hostname"]) & set(test_df["hostname"])

print(f"Hostname overlap: {len(overlap)}")

if overlap:
    raise RuntimeError(
        "ERROR: Hostnames overlap between training and testing sets."
    )

# -------------------------------------------------------------------
# 4. Load trained model bundle
# -------------------------------------------------------------------

print("\nLoading trained model...")

bundle = joblib.load(MODEL_PATH)

model = bundle["model"]
vectorizer = bundle["vectorizer"]
imputer = bundle["imputer"]
scaler = bundle["scaler"]
numeric_features = bundle["numeric_features"]

# -------------------------------------------------------------------
# 5. Extract numeric features
# -------------------------------------------------------------------

print("\nExtracting test URL features...")

numeric_rows = [
    extract_dataset_features(url)
    for url in test_df["URL"]
]

numeric_df = pd.DataFrame(numeric_rows)

numeric_df = numeric_df[numeric_features]

numeric_values = imputer.transform(numeric_df)
numeric_values = scaler.transform(numeric_values)

# -------------------------------------------------------------------
# 6. Character TF-IDF
# -------------------------------------------------------------------

print("Building character TF-IDF features...")

tfidf_values = vectorizer.transform(test_df["URL"])

final_features = hstack(
    [
        tfidf_values,
        csr_matrix(numeric_values),
    ]
).tocsr()

# -------------------------------------------------------------------
# 7. Predictions
# -------------------------------------------------------------------

print("Running predictions...")

y_true = test_df["label"].astype(int).values

y_pred = model.predict(final_features)
y_probability = model.predict_proba(final_features)[:, 1]

# -------------------------------------------------------------------
# 8. Metrics
# -------------------------------------------------------------------

accuracy = accuracy_score(y_true, y_pred)
precision = precision_score(y_true, y_pred, zero_division=0)
recall = recall_score(y_true, y_pred, zero_division=0)
f1 = f1_score(y_true, y_pred, zero_division=0)
roc_auc = roc_auc_score(y_true, y_probability)

cm = confusion_matrix(y_true, y_pred)

print("\n")
print("=" * 70)
print("DOMAIN-AWARE MODEL PERFORMANCE")
print("=" * 70)

print(f"Accuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1 Score : {f1:.4f}")
print(f"ROC-AUC  : {roc_auc:.4f}")

print("\nConfusion Matrix:")
print(cm)

# -------------------------------------------------------------------
# 9. Class distribution
# -------------------------------------------------------------------

print("\nTest class distribution:")
print(
    pd.Series(y_true)
    .value_counts()
    .sort_index()
    .rename(index={
        0: "Legitimate",
        1: "Phishing",
    })
)

# -------------------------------------------------------------------
# 10. Example predictions
# -------------------------------------------------------------------

results = test_df[
    ["URL", "hostname", "label"]
].copy()

results["prediction"] = y_pred
results["phishing_probability"] = y_probability

print("\nSample predictions:")
print("-" * 70)

sample = results.sample(
    min(20, len(results)),
    random_state=RANDOM_STATE
)

for _, row in sample.iterrows():
    actual = "PHISHING" if row["label"] == 1 else "LEGITIMATE"
    predicted = "PHISHING" if row["prediction"] == 1 else "LEGITIMATE"
    probability = row["phishing_probability"] * 100

    print(
        f"{predicted:10s} | "
        f"{probability:6.2f}% | "
        f"Actual: {actual:10s} | "
        f"{row['URL']}"
    )

# -------------------------------------------------------------------
# 11. Analyze model errors
# -------------------------------------------------------------------

false_negatives = results[
    (results["label"] == 1) &
    (results["prediction"] == 0)
].copy()

false_positives = results[
    (results["label"] == 0) &
    (results["prediction"] == 1)
].copy()

print("\n")
print("=" * 70)
print("ERROR ANALYSIS")
print("=" * 70)

print(f"\nFalse Negatives (phishing predicted as legitimate): {len(false_negatives)}")
print(f"False Positives (legitimate predicted as phishing): {len(false_positives)}")

print("\n" + "-" * 70)
print("TOP FALSE NEGATIVES")
print("-" * 70)

if len(false_negatives) > 0:
    false_negatives = false_negatives.sort_values(
        "phishing_probability",
        ascending=True
    )

    for _, row in false_negatives.head(20).iterrows():
        print(
            f"{row['phishing_probability'] * 100:6.2f}% | "
            f"{row['URL']}"
        )
else:
    print("No false negatives found.")

print("\n" + "-" * 70)
print("TOP FALSE POSITIVES")
print("-" * 70)

if len(false_positives) > 0:
    false_positives = false_positives.sort_values(
        "phishing_probability",
        ascending=False
    )

    for _, row in false_positives.head(20).iterrows():
        print(
            f"{row['phishing_probability'] * 100:6.2f}% | "
            f"{row['URL']}"
        )
else:
    print("No false positives found.")

print("\nEvaluation completed.")