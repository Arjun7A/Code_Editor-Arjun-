"""
Synthetic PR Data Generator for XGBoost Risk Model
===================================================
Generates ~1000 realistic labeled Pull Request records with 12 features.
Labels are assigned using rule-based logic that mirrors real security signals.
"""

import pandas as pd
import numpy as np
import os
import sys

# ── Configuration ────────────────────────────────────────────────────────────
NUM_SAMPLES = 1200
RANDOM_SEED = 42
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "processed")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "pr_features.csv")

# Feature names (12 total)
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


def generate_pr_data(n_samples: int, seed: int = 42) -> pd.DataFrame:
    """Generate synthetic PR feature data with realistic distributions."""
    rng = np.random.RandomState(seed)

    data = {
        # Number of files changed – right-skewed (most PRs touch few files)
        "files_changed": rng.lognormal(mean=1.5, sigma=1.0, size=n_samples)
        .astype(int)
        .clip(1, 500),
        # Lines added – right-skewed
        "lines_added": rng.lognormal(mean=3.5, sigma=1.5, size=n_samples)
        .astype(int)
        .clip(0, 50000),
        # Lines deleted – correlated with lines added but smaller
        "lines_deleted": rng.lognormal(mean=2.5, sigma=1.5, size=n_samples)
        .astype(int)
        .clip(0, 30000),
        # Commit count per PR
        "commit_count": rng.poisson(lam=3, size=n_samples).clip(1, 50),
        # Author reputation score (0-1), skewed toward higher values
        "author_reputation": rng.beta(a=5, b=2, size=n_samples).round(3),
        # Hour of day (0-23)
        "time_of_day": rng.randint(0, 24, size=n_samples),
        # Day of week (0=Mon, 6=Sun)
        "day_of_week": rng.randint(0, 7, size=n_samples),
        # Whether test files were modified (boolean)
        "has_test_changes": rng.binomial(1, 0.4, size=n_samples),
        # Number of linked issues
        "num_issues": rng.poisson(lam=1.5, size=n_samples).clip(0, 20),
        # Count of high/critical severity findings from scanners
        "num_severity": rng.poisson(lam=0.8, size=n_samples).clip(0, 15),
        # JS/PY code ratio (0-1)
        "lang_ratio": rng.beta(a=2, b=3, size=n_samples).round(3),
        # Author's historical vulnerability introduction rate (0-1)
        "historical_vuln_rate": rng.beta(a=1.5, b=10, size=n_samples).round(4),
    }

    return pd.DataFrame(data)


def label_risk(df: pd.DataFrame) -> pd.Series:
    """
    Assign risk labels using rule-based logic that mirrors real security signals.
    
    HIGH RISK (1) indicators:
    - Many high/critical severity findings
    - Large PRs from low-reputation authors
    - High historical vulnerability rate
    - No test changes on large code modifications
    - Late-night or weekend PRs with security concerns
    
    Returns: Series of 0 (low risk) / 1 (high risk)
    """
    risk_score = np.zeros(len(df), dtype=float)

    # ── Primary signals ──────────────────────────────────────────────────
    # Severity findings are the strongest indicator
    risk_score += df["num_severity"] * 0.25

    # Large PRs with many files are riskier
    risk_score += np.where(df["files_changed"] > 20, 0.15, 0)
    risk_score += np.where(df["lines_added"] > 500, 0.10, 0)
    risk_score += np.where(df["lines_added"] > 2000, 0.15, 0)

    # Low author reputation increases risk
    risk_score += np.where(df["author_reputation"] < 0.3, 0.20, 0)
    risk_score += np.where(df["author_reputation"] < 0.5, 0.05, 0)

    # Historical vulnerability rate
    risk_score += df["historical_vuln_rate"] * 0.8

    # ── Secondary signals ────────────────────────────────────────────────
    # No tests on large changes is suspicious
    risk_score += np.where(
        (df["has_test_changes"] == 0) & (df["lines_added"] > 200), 0.10, 0
    )

    # Late night (10 PM - 5 AM) or weekend PRs with other risk factors
    late_night = (df["time_of_day"] >= 22) | (df["time_of_day"] <= 5)
    weekend = df["day_of_week"] >= 5
    risk_score += np.where(late_night & (df["num_severity"] > 0), 0.05, 0)
    risk_score += np.where(weekend & (df["num_severity"] > 0), 0.05, 0)

    # Many commits can indicate messy history
    risk_score += np.where(df["commit_count"] > 10, 0.05, 0)

    # ── Add noise for realism ────────────────────────────────────────────
    noise = np.random.RandomState(42).normal(0, 0.05, len(df))
    risk_score += noise

    # ── Binary classification threshold ──────────────────────────────────
    # Aim for ~35% high-risk (realistic class imbalance)
    threshold = np.percentile(risk_score, 65)
    labels = (risk_score >= threshold).astype(int)

    return labels


def main():
    """Generate and save the training dataset."""
    print("=" * 60)
    print("  Synthetic PR Data Generator")
    print("=" * 60)

    # Generate features
    print(f"\n[1/3] Generating {NUM_SAMPLES} synthetic PR records...")
    df = generate_pr_data(NUM_SAMPLES, seed=RANDOM_SEED)

    # Assign labels
    print("[2/3] Assigning risk labels with rule-based logic...")
    df["high_risk"] = label_risk(df)

    # Save to CSV
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    df.to_csv(OUTPUT_FILE, index=False)
    print(f"[3/3] Saved dataset to: {OUTPUT_FILE}")

    # Print summary statistics
    print(f"\n{'─' * 40}")
    print(f"  Dataset Summary")
    print(f"{'─' * 40}")
    print(f"  Total samples:  {len(df)}")
    print(f"  Features:       {len(FEATURE_NAMES)}")
    print(f"  High risk (1):  {df['high_risk'].sum()} ({df['high_risk'].mean()*100:.1f}%)")
    print(f"  Low risk  (0):  {(1 - df['high_risk']).sum()} ({(1 - df['high_risk'].mean())*100:.1f}%)")
    print(f"\n  Feature stats:")
    print(df[FEATURE_NAMES].describe().round(2).to_string())
    print()

    return df


if __name__ == "__main__":
    main()
