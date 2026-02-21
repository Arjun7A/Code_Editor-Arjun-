"""
ML Predictor Service
=====================
Loads the trained XGBoost model and provides risk predictions.
Caches the model in memory after first load.
"""

import os
import logging
import joblib
import numpy as np
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# Feature names expected by the model (must match training order)
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


class MLPredictor:
    """Singleton-style ML predictor that caches the model in memory."""

    _instance: Optional["MLPredictor"] = None
    _model = None
    _model_loaded = False

    def __new__(cls, model_path: str = None):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, model_path: str = None):
        if model_path and not self._model_loaded:
            self._model_path = model_path

    def _load_model(self):
        """Load the model from disk (called once, then cached)."""
        if self._model_loaded:
            return

        try:
            # Resolve path relative to backend dir
            model_path = self._model_path
            if not os.path.isabs(model_path):
                base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
                model_path = os.path.join(base_dir, model_path)

            if not os.path.exists(model_path):
                logger.warning(f"ML model not found at {model_path}. Using fallback heuristic.")
                self._model = None
                self._model_loaded = True
                return

            self._model = joblib.load(model_path)
            self._model_loaded = True
            logger.info(f"ML model loaded successfully from {model_path}")

        except Exception as e:
            logger.error(f"Failed to load ML model: {e}")
            self._model = None
            self._model_loaded = True

    def predict_risk(self, features: Dict[str, float]) -> Dict:
        """
        Predict risk score for a PR based on its features.

        Args:
            features: dict with keys matching FEATURE_NAMES

        Returns:
            dict with risk_score (0-1), risk_label, per-PR feature contributions
        """
        self._load_model()

        # Build feature vector in correct order
        feature_vector = []
        for name in FEATURE_NAMES:
            value = features.get(name, 0)
            # Convert booleans to int
            if isinstance(value, bool):
                value = int(value)
            feature_vector.append(float(value))

        feature_array = np.array([feature_vector])

        if self._model is not None:
            # Use trained model
            try:
                risk_probability = float(self._model.predict_proba(feature_array)[0][1])
                risk_prediction = int(self._model.predict(feature_array)[0])

                # Compute per-prediction feature contributions:
                # Multiply each feature's value by global importance
                # to get per-PR "contribution" (then normalise to sum=1).
                global_importances = self._model.feature_importances_
                raw_contributions = []
                for i, name in enumerate(FEATURE_NAMES):
                    raw_contributions.append(abs(feature_vector[i]) * global_importances[i])
                total = sum(raw_contributions) or 1.0
                importance_dict = {
                    name: round(c / total, 4)
                    for name, c in zip(FEATURE_NAMES, raw_contributions)
                }

                return {
                    "risk_score": round(risk_probability, 4),
                    "risk_label": "high" if risk_prediction == 1 else "low",
                    "risk_percentage": round(risk_probability * 100, 1),
                    "feature_importance": importance_dict,
                    "model_version": "xgboost_v1",
                    "using_fallback": False,
                }

            except Exception as e:
                logger.error(f"Model prediction failed: {e}")
                return self._fallback_prediction(features)
        else:
            return self._fallback_prediction(features)

    def _fallback_prediction(self, features: Dict[str, float]) -> Dict:
        """
        Heuristic fallback when the ML model is unavailable.
        Uses the same logic as the original analyze.py formula.
        """
        critical = features.get("num_severity", 0)
        files = features.get("files_changed", 0)
        reputation = features.get("author_reputation", 0.5)
        vuln_rate = features.get("historical_vuln_rate", 0)
        has_tests = features.get("has_test_changes", 0)

        score = 0.0
        score += min(critical * 0.15, 0.45)
        score += min(files * 0.005, 0.15)
        score += max(0, (1 - reputation) * 0.2)
        score += vuln_rate * 0.15
        if not has_tests and files > 5:
            score += 0.05

        score = max(0, min(1, score))

        return {
            "risk_score": round(score, 4),
            "risk_label": "high" if score >= 0.5 else "low",
            "risk_percentage": round(score * 100, 1),
            "feature_importance": {},
            "model_version": "fallback_heuristic",
            "using_fallback": True,
        }

    @classmethod
    def reset(cls):
        """Reset the singleton (mainly for testing)."""
        cls._instance = None
        cls._model = None
        cls._model_loaded = False
