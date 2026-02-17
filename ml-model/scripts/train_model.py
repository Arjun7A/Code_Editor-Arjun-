"""
XGBoost Model Training Pipeline
================================
Loads the generated PR features, trains an XGBoost classifier,
evaluates performance, and saves the trained model.
"""

import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for saving plots
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix,
)
from xgboost import XGBClassifier

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.join(os.path.dirname(__file__), "..")
DATA_FILE = os.path.join(BASE_DIR, "data", "processed", "pr_features.csv")
MODEL_DIR = os.path.join(BASE_DIR, "models")
MODEL_FILE = os.path.join(MODEL_DIR, "xgboost_v1.pkl")
METRICS_FILE = os.path.join(MODEL_DIR, "metrics.json")
IMPORTANCE_PLOT = os.path.join(MODEL_DIR, "feature_importance.png")

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


def load_data():
    """Load and validate the dataset."""
    if not os.path.exists(DATA_FILE):
        print(f"ERROR: Dataset not found at {DATA_FILE}")
        print("Run collect_data.py first to generate the dataset.")
        sys.exit(1)

    df = pd.read_csv(DATA_FILE)
    print(f"Loaded {len(df)} records with {len(df.columns)} columns")

    # Validate columns
    missing = set(FEATURE_NAMES + [TARGET]) - set(df.columns)
    if missing:
        print(f"ERROR: Missing columns: {missing}")
        sys.exit(1)

    return df


def train_model(X_train, y_train):
    """Train XGBoost with hyperparameter tuning via GridSearchCV."""
    print("\n[2/5] Training XGBoost with hyperparameter search...")

    # Base model
    base_model = XGBClassifier(
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=RANDOM_SEED,
        use_label_encoder=False,
    )

    # Hyperparameter grid
    param_grid = {
        "n_estimators": [100, 200, 300],
        "max_depth": [3, 5, 7],
        "learning_rate": [0.01, 0.1, 0.2],
        "subsample": [0.8, 1.0],
        "colsample_bytree": [0.8, 1.0],
        "min_child_weight": [1, 3],
    }

    # Use a smaller grid for speed (picks best from strategic combos)
    param_grid_fast = {
        "n_estimators": [100, 200],
        "max_depth": [4, 6],
        "learning_rate": [0.05, 0.1],
        "subsample": [0.8],
        "colsample_bytree": [0.8],
        "min_child_weight": [1, 3],
    }

    grid_search = GridSearchCV(
        estimator=base_model,
        param_grid=param_grid_fast,
        cv=5,
        scoring="roc_auc",
        n_jobs=-1,
        verbose=1,
    )

    grid_search.fit(X_train, y_train)

    print(f"\n  Best params: {grid_search.best_params_}")
    print(f"  Best CV ROC-AUC: {grid_search.best_score_:.4f}")

    return grid_search.best_estimator_


def evaluate_model(model, X_test, y_test):
    """Evaluate model and return metrics dict."""
    print("\n[3/5] Evaluating model on test set...")

    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_proba)
    cm = confusion_matrix(y_test, y_pred)

    print(f"\n  Accuracy:  {acc:.4f}")
    print(f"  F1 Score:  {f1:.4f}")
    print(f"  ROC-AUC:   {roc_auc:.4f}")
    print(f"\n  Confusion Matrix:")
    print(f"    TN={cm[0][0]}  FP={cm[0][1]}")
    print(f"    FN={cm[1][0]}  TP={cm[1][1]}")
    print(f"\n  Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Low Risk", "High Risk"]))

    metrics = {
        "accuracy": round(acc, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(roc_auc, 4),
        "confusion_matrix": cm.tolist(),
        "test_size": len(y_test),
        "train_size": len(y_test) * 4,  # approx from 80/20 split
    }

    return metrics


def plot_feature_importance(model, feature_names):
    """Save feature importance plot."""
    print("[4/5] Generating feature importance plot...")

    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]

    fig, ax = plt.subplots(figsize=(10, 6))
    colors = plt.cm.RdYlGn_r(importances[indices] / importances.max())

    ax.barh(
        range(len(feature_names)),
        importances[indices],
        color=colors,
        edgecolor="#333",
        linewidth=0.5,
    )
    ax.set_yticks(range(len(feature_names)))
    ax.set_yticklabels([feature_names[i] for i in indices], fontsize=11)
    ax.set_xlabel("Feature Importance (Gain)", fontsize=12)
    ax.set_title("XGBoost Feature Importance — PR Risk Prediction", fontsize=14, fontweight="bold")
    ax.invert_yaxis()

    plt.tight_layout()
    plt.savefig(IMPORTANCE_PLOT, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Saved to: {IMPORTANCE_PLOT}")


def save_model(model, metrics):
    """Save the trained model and metrics."""
    print("[5/5] Saving model and metrics...")

    os.makedirs(MODEL_DIR, exist_ok=True)

    # Save model
    joblib.dump(model, MODEL_FILE)
    print(f"  Model saved to: {MODEL_FILE}")

    # Save metrics
    with open(METRICS_FILE, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"  Metrics saved to: {METRICS_FILE}")


def main():
    print("=" * 60)
    print("  XGBoost Model Training Pipeline")
    print("=" * 60)

    # 1. Load data
    print("\n[1/5] Loading dataset...")
    df = load_data()
    X = df[FEATURE_NAMES]
    y = df[TARGET]

    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_SEED, stratify=y
    )
    print(f"  Train: {len(X_train)} | Test: {len(X_test)}")

    # 2. Train
    model = train_model(X_train, y_train)

    # 3. Evaluate
    metrics = evaluate_model(model, X_test, y_test)

    # 4. Feature importance
    plot_feature_importance(model, FEATURE_NAMES)

    # 5. Save
    save_model(model, metrics)

    # Summary
    print(f"\n{'=' * 60}")
    print(f"  Training Complete!")
    print(f"{'=' * 60}")
    print(f"  Model: {MODEL_FILE}")
    print(f"  Accuracy: {metrics['accuracy']}")
    print(f"  F1 Score: {metrics['f1_score']}")
    print(f"  ROC-AUC:  {metrics['roc_auc']}")
    print()

    return model, metrics


if __name__ == "__main__":
    main()
