"""Risk model: train a Random Forest and score open ports as low, medium, or high.

Labels come from a documented rule table (see data/build_dataset.py), not from
real incident data.
"""
import json
import re
import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

sys.path.insert(0, str(Path(__file__).resolve().parent))
from data.build_dataset import LABELS, RULES

ROOT = Path(__file__).resolve().parent
DATASET_PATH = ROOT / "data" / "ports_dataset.csv"
MODEL_PATH = ROOT / "risk_model.joblib"
METRICS_PATH = ROOT / "metrics" / "model_metrics.json"

FEATURES = ["service", "encrypted", "version_known", "version_lag"]

# Approximate latest "major.minor" versions, used to estimate how far behind a
# detected version is. These are rough and will go stale. Update them as needed.
REFERENCE_VERSIONS = {
    "openssh": (9, 9), "nginx": (1, 27), "apache": (2, 4), "mysql": (8, 4),
    "postgresql": (17, 0), "redis": (7, 4), "mongodb": (8, 0),
    "vsftpd": (3, 0), "proftpd": (1, 3), "samba": (4, 20),
}


def version_lag(version_text):
    """Estimate how many version steps behind the latest (0 to 20)."""
    text = (version_text or "").lower()
    match = re.search(r"(\d+)\.(\d+)", text)
    if not match:
        return 0
    major, minor = int(match.group(1)), int(match.group(2))
    for product, (ref_major, ref_minor) in REFERENCE_VERSIONS.items():
        if product in text:
            lag = (ref_major - major) * 10 + (ref_minor - minor)
            return max(0, min(20, lag))
    return 0  # product not in the reference table


def make_features(port):
    """Turn one scanner result (a dict) into the model's feature row."""
    service = (port.get("service") or "other").lower()
    if service not in RULES:
        service = "other"
    version = port.get("version") or ""
    return {
        "service": service,
        "encrypted": 1 if port.get("encrypted") == "yes" else 0,
        "version_known": 1 if version.strip() else 0,
        "version_lag": version_lag(version),
    }


def train(dataset_path=DATASET_PATH, model_path=MODEL_PATH, metrics_path=METRICS_PATH):
    """Train on the dataset, save the model, and write the metrics file."""
    df = pd.read_csv(dataset_path)
    X, y = df[FEATURES], df["risk"]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    pipeline = Pipeline([
        ("prep", ColumnTransformer(
            [("service", OneHotEncoder(handle_unknown="ignore"), ["service"])],
            remainder="passthrough",
        )),
        ("forest", RandomForestClassifier(n_estimators=100, min_samples_leaf=5, random_state=42)),
    ])
    pipeline.fit(X_train, y_train)

    pred = pipeline.predict(X_test)
    metrics = {
        "accuracy": round(accuracy_score(y_test, pred), 4),
        "macro_f1": round(f1_score(y_test, pred, average="macro"), 4),
        "confusion_matrix": {
            "labels": LABELS,  # rows are true labels, columns are predictions
            "matrix": confusion_matrix(y_test, pred, labels=LABELS).tolist(),
        },
        "train_rows": len(X_train),
        "test_rows": len(X_test),
        "label_source": "documented rule table based on CVSS severity knowledge, not real incident data",
    }

    Path(metrics_path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, model_path)
    Path(metrics_path).write_text(json.dumps(metrics, indent=2))
    return metrics


_model = None


def load_model(model_path=MODEL_PATH):
    """Load the saved model once and reuse it."""
    global _model
    if _model is None:
        _model = joblib.load(model_path)
    return _model


def predict_ports(ports, model=None):
    """Add risk, risk_score, and confidence to each port dict.

    risk_score runs from 0 to 1 (medium counts half, high counts full) and is
    used to rank ports. Results are sorted riskiest first.
    """
    if not ports:
        return []
    model = model or load_model()
    rows = pd.DataFrame([make_features(p) for p in ports], columns=FEATURES)
    probs = model.predict_proba(rows)
    classes = list(model.classes_)

    scored = []
    for port, p in zip(ports, probs):
        by_class = dict(zip(classes, p))
        risk = max(by_class, key=by_class.get)
        scored.append({
            **port,
            "risk": risk,
            "risk_score": round(by_class.get("medium", 0) * 0.5 + by_class.get("high", 0), 3),
            "confidence": round(by_class[risk], 3),
        })
    return sorted(scored, key=lambda r: r["risk_score"], reverse=True)


if __name__ == "__main__":
    result = train()
    print(json.dumps(result, indent=2))
