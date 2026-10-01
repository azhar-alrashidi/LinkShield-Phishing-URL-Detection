"""Train the LinkShield Random Forest model.

Usage (from the project root):  python models/train.py
Expects data/phishing_site_urls.csv with columns: URL, Label (good/bad).
"""
import os
import re
import sys
from urllib.parse import urlparse

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from analyze import FEATURE_NAMES, extract_features  # noqa: E402

DATASET_PATH = os.path.join(HERE, "..", "data", "phishing_site_urls.csv")
MODEL_PATH = os.path.join(HERE, "linkshield_model.pkl")
MAX_SAFE_SAMPLES = 350_000


def clean_url(url):
    if pd.isna(url):
        return None
    url = str(url).strip().lower()
    if url in ("", "nan", "none", "null"):
        return None
    url = re.sub(r"\s+", "", url)
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    if url.count("[") != url.count("]"):
        return None
    try:
        netloc = urlparse(url).netloc
    except ValueError:
        return None
    return url if netloc and "." in netloc else None


def build_features(urls, label):
    rows = (extract_features(u, label) for u in urls)
    return pd.DataFrame([r for r in rows if r is not None], columns=FEATURE_NAMES)


def main():
    print("Loading dataset...")
    df = pd.read_csv(DATASET_PATH, dtype=str, keep_default_na=False, encoding="utf-8")
    df = df.drop_duplicates().dropna()
    df["Label"] = df["Label"].str.lower().map({"good": 0, "bad": 1})
    df = df.dropna(subset=["Label"])

    good, bad = df[df["Label"] == 0].copy(), df[df["Label"] == 1].copy()
    print(f"Safe: {len(good):,} | Malicious: {len(bad):,}")

    # Undersample the safe class to balance the dataset
    good = good.sample(n=min(MAX_SAFE_SAMPLES, len(good)), random_state=42)

    good["clean_url"] = good["URL"].apply(clean_url)
    bad["clean_url"] = bad["URL"].apply(clean_url)
    good, bad = good[good["clean_url"].notna()], bad[bad["clean_url"].notna()]
    print(f"After cleaning - Safe: {len(good):,} | Malicious: {len(bad):,}")

    print("Extracting features...")
    data = pd.concat([build_features(good["clean_url"], 0),
                      build_features(bad["clean_url"], 1)])
    data = data.sample(frac=1, random_state=42).reset_index(drop=True)

    X, y = data.drop(columns=["result"]), data["result"]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)

    print("Training model...")
    pipeline = Pipeline([
        ("classifier", RandomForestClassifier(
            n_estimators=100, max_depth=15, min_samples_split=20,
            min_samples_leaf=10, max_features="sqrt", random_state=42,
            class_weight={0: 1, 1: 2}, n_jobs=-1)),
    ])
    pipeline.fit(X_train, y_train)

    print(f"\nTrain accuracy: {pipeline.score(X_train, y_train) * 100:.2f}%")
    print(f"Test accuracy:  {pipeline.score(X_test, y_test) * 100:.2f}%")
    y_pred = pipeline.predict(X_test)
    print(classification_report(y_test, y_pred, target_names=["SAFE", "MALICIOUS"]))

    cm = confusion_matrix(y_test, y_pred)
    print("Confusion matrix:")
    print(f"  Safe -> Safe:           {cm[0][0]:,}")
    print(f"  Safe -> Malicious:      {cm[0][1]:,}")
    print(f"  Malicious -> Safe:      {cm[1][0]:,}  <- missed threats")
    print(f"  Malicious -> Malicious: {cm[1][1]:,}")

    importances = pd.Series(pipeline.named_steps["classifier"].feature_importances_,
                            index=X.columns)
    print("\nTop 10 features:")
    print(importances.nlargest(10).to_string())

    joblib.dump(pipeline, MODEL_PATH)
    print(f"\nModel saved to: {MODEL_PATH}")


if __name__ == "__main__":
    main()
