from pathlib import Path

import pandas as pd


INPUT_FILE = Path("data/raw/url_features_extracted1.csv")
OUTPUT_FILE = Path("data/processed/phishing_urls_clean.csv")


def main():
    print("=" * 60)
    print("PhishGuard AI - Dataset Preparation")
    print("=" * 60)

    # Load dataset
    df = pd.read_csv(INPUT_FILE)

    print(f"\nOriginal rows: {len(df):,}")
    print(f"Original columns: {len(df.columns)}")

    # Keep only rows with a URL and a valid label
    df = df.dropna(subset=["URL", "ClassLabel"])

    # Normalize URL representation
    df["URL"] = df["URL"].astype(str).str.strip()

    # Remove empty URLs
    df = df[df["URL"] != ""]

    # Keep only binary labels
    df = df[df["ClassLabel"].isin([0, 1, 0.0, 1.0])]

    # Convert labels to integers
    df["ClassLabel"] = df["ClassLabel"].astype(int)

    # Remove duplicate URLs
    before_duplicates = len(df)
    df = df.drop_duplicates(subset=["URL"], keep="first")
    duplicates_removed = before_duplicates - len(df)

    # Create output directory
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Save cleaned dataset
    df.to_csv(OUTPUT_FILE, index=False)

    print("\nCleaning results")
    print("-" * 60)
    print(f"Rows after cleaning: {len(df):,}")
    print(f"Duplicate URLs removed: {duplicates_removed:,}")
    print(f"Missing URLs remaining: {df['URL'].isna().sum()}")
    print(f"Missing labels remaining: {df['ClassLabel'].isna().sum()}")

    print("\nClass distribution")
    print("-" * 60)

    counts = df["ClassLabel"].value_counts().sort_index()

    for label, count in counts.items():
        percentage = count / len(df) * 100
        print(f"Class {label}: {count:,} ({percentage:.2f}%)")

    print("\nSaved to:")
    print(OUTPUT_FILE)

    print("\nDataset preparation completed successfully.")


if __name__ == "__main__":
    main()