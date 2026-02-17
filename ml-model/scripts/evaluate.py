"""
Model Evaluation Script
========================
Loads the saved XGBoost model and generates detailed evaluation metrics,
classification report, and ROC curve plot.
"""

import os
import sys
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    roc_auc_score,
    roc_curve,
    precision_recall_curve,
    classification_report,
    confusion_matrix,
)

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.join(os.path.dirname(__file__), "..")
DATA_FILE = os.path.join(BASE_DIR, "data", "processed", "pr_features.csv")
MODEL_DIR = os.path.join(BASE_DIR, "models")
MODEL_FILE = os.path.join(MODEL_DIR, "xgboost_v1.pkl")
ROC_PLOT = os.path.join(MODEL_DIR, "roc_curve.png")
PR_PLOT = os.path.join(MODEL_DIR, "precision_recall_curve.png")

FEATURE_NAMES = [
    "files_changed",
    "lines_added",
    "lines_deleted",
    "commit_count",
    "author_reputation",
    "time_of_day",
    "day_of_week",
    "has_test_changes",
    "num_issues",
    "num_severity",
    "lang_ratio",
    "historical_vuln_rate",
]
TARGET = "high_risk"
TEST_SIZE = 0.2
RANDOM_SEED = 42


def load_model_and_data():
    """Load saved model and original dataset."""
    if not os.path.exists(MODEL_FILE):
        print(f"ERROR: Model not found at {MODEL_FILE}")
        print("Run train_model.py first.")
        sys.exit(1)

    if not os.path.exists(DATA_FILE):
        print(f"ERROR: Dataset not found at {DATA_FILE}")
        print("Run collect_data.py first.")
        sys.exit(1)

    model = joblib.load(MODEL_FILE)
    df = pd.read_csv(DATA_FILE)
    return model, df


def plot_roc_curve(y_test, y_proba):
    """Generate and save ROC curve."""
    fpr, tpr, thresholds = roc_curve(y_test, y_proba)
    auc = roc_auc_score(y_test, y_proba)

    fig, ax = plt.subplots(figsize=(8, 6))
    ax.plot(fpr, tpr, color="#2563eb", linewidth=2.5, label=f"XGBoost (AUC = {auc:.3f})")
    ax.plot([0, 1], [0, 1], color="#94a3b8", linestyle="--", linewidth=1, label="Random (AUC = 0.500)")
    ax.fill_between(fpr, tpr, alpha=0.1, color="#2563eb")

    ax.set_xlabel("False Positive Rate", fontsize=12)
    ax.set_ylabel("True Positive Rate", fontsize=12)
    ax.set_title("ROC Curve — PR Risk Classification", fontsize=14, fontweight="bold")
    ax.legend(loc="lower right", fontsize=11)
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(ROC_PLOT, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  ROC curve saved to: {ROC_PLOT}")


def plot_precision_recall(y_test, y_proba):
    """Generate and save precision-recall curve."""
    precision, recall, thresholds = precision_recall_curve(y_test, y_proba)

    fig, ax = plt.subplots(figsize=(8, 6))
    ax.plot(recall, precision, color="#dc2626", linewidth=2.5, label="XGBoost")
    ax.fill_between(recall, precision, alpha=0.1, color="#dc2626")

    ax.set_xlabel("Recall", fontsize=12)
    ax.set_ylabel("Precision", fontsize=12)
    ax.set_title("Precision-Recall Curve — PR Risk Classification", fontsize=14, fontweight="bold")
    ax.legend(loc="upper right", fontsize=11)
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(PR_PLOT, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  PR curve saved to: {PR_PLOT}")


def main():
    print("=" * 60)
    print("  Model Evaluation Report")
    print("=" * 60)

    # Load model and data
    print("\n[1/4] Loading model and data...")
    model, df = load_model_and_data()

    X = df[FEATURE_NAMES]
    y = df[TARGET]

    # Use same split as training
    _, X_test, _, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_SEED, stratify=y
    )
    print(f"  Evaluating on {len(X_test)} test samples")

    # Predictions
    print("\n[2/4] Generating predictions...")
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    # Metrics
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_proba)
    cm = confusion_matrix(y_test, y_pred)

    print(f"\n{'─' * 50}")
    print(f"  EVALUATION RESULTS")
    print(f"{'─' * 50}")
    print(f"  Accuracy:     {acc:.4f}  {'✅' if acc >= 0.75 else '⚠️'} (target: ≥0.75)")
    print(f"  F1 Score:     {f1:.4f}  {'✅' if f1 >= 0.80 else '⚠️'} (target: ≥0.80)")
    print(f"  ROC-AUC:      {roc_auc:.4f}  {'✅' if roc_auc >= 0.85 else '⚠️'} (target: ≥0.85)")
    print(f"\n  Confusion Matrix:")
    print(f"                Predicted")
    print(f"               Low   High")
    print(f"  Actual Low  [{cm[0][0]:>4}  {cm[0][1]:>4}]")
    print(f"  Actual High [{cm[1][0]:>4}  {cm[1][1]:>4}]")
    print(f"\n  Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Low Risk", "High Risk"]))

    # Plots
    print("[3/4] Generating ROC curve...")
    plot_roc_curve(y_test, y_proba)

    print("[4/4] Generating precision-recall curve...")
    plot_precision_recall(y_test, y_proba)

    # Sample predictions
    print(f"\n{'─' * 50}")
    print(f"  SAMPLE PREDICTIONS (first 5 test records)")
    print(f"{'─' * 50}")
    sample_df = X_test.head(5).copy()
    sample_df["actual"] = y_test.head(5).values
    sample_df["predicted"] = y_pred[:5]
    sample_df["risk_probability"] = y_proba[:5].round(4)
    print(sample_df[["files_changed", "num_severity", "author_reputation", "actual", "predicted", "risk_probability"]].to_string())

    print(f"\n{'=' * 60}")
    print(f"  Evaluation Complete!")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()
