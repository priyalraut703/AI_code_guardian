"""
risk_classifier.py
Lightweight ML risk predictor using RandomForestClassifier.
Trains on synthetic data derived from code metrics and predicts risk level.
"""

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from typing import Dict, Tuple


# ── Synthetic training data ───────────────────────────────────────────────────
# Features: [lines, loops, conditions, variables, nesting_depth, functions]
# Labels:   0=Low, 1=Medium, 2=High

_TRAINING_DATA = np.array(
    [
        # Low risk: small, simple scripts
        [10, 0, 1, 3, 0, 1],
        [15, 1, 2, 5, 1, 1],
        [8,  0, 0, 2, 0, 0],
        [20, 1, 1, 4, 1, 2],
        [12, 0, 2, 3, 0, 1],
        [5,  0, 0, 1, 0, 0],
        [18, 1, 3, 6, 1, 2],
        [25, 2, 2, 7, 1, 3],
        # Medium risk: moderate complexity
        [40, 3, 5, 10, 2, 4],
        [60, 4, 6, 12, 2, 5],
        [35, 3, 4, 9,  2, 3],
        [50, 4, 5, 11, 2, 4],
        [45, 3, 7, 13, 2, 5],
        [55, 5, 5, 10, 2, 4],
        [30, 2, 6, 8,  2, 3],
        [70, 4, 8, 15, 3, 6],
        # High risk: complex, deeply nested
        [100, 8,  10, 20, 4, 8],
        [150, 10, 15, 25, 5, 10],
        [90,  7,  9,  18, 4, 7],
        [120, 9,  12, 22, 4, 9],
        [200, 12, 20, 30, 6, 12],
        [80,  8,  11, 17, 3, 8],
        [130, 10, 14, 24, 5, 10],
        [180, 11, 18, 28, 5, 11],
    ],
    dtype=float,
)

_TRAINING_LABELS = np.array(
    [0, 0, 0, 0, 0, 0, 0, 0,   # Low
     1, 1, 1, 1, 1, 1, 1, 1,   # Medium
     2, 2, 2, 2, 2, 2, 2, 2],  # High
)

_LABEL_MAP = {0: "🟢 Low Risk", 1: "🟡 Medium Risk", 2: "🔴 High Risk"}
_LABEL_COLORS = {0: "#22c55e", 1: "#eab308", 2: "#ef4444"}


class RiskClassifier:
    """
    Wraps a RandomForestClassifier trained on synthetic code metrics.
    """

    def __init__(self):
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=6,
            random_state=42,
        )
        self._trained = False
        self._train()

    def _train(self):
        """Train the model on the built-in synthetic dataset."""
        self.model.fit(_TRAINING_DATA, _TRAINING_LABELS)
        self._trained = True

    def predict(self, metrics: Dict) -> Dict:
        """
        Predict risk from code metrics.

        Args:
            metrics: dict from code_parser.parse_code()

        Returns:
            dict with keys: label, color, probability, class_index, feature_importances
        """
        features = np.array(
            [
                [
                    metrics.get("number_of_lines", 0),
                    metrics.get("number_of_loops", 0),
                    metrics.get("number_of_conditions", 0),
                    metrics.get("number_of_variables", 0),
                    metrics.get("max_nesting_depth", 0),
                    metrics.get("number_of_functions", 0),
                ]
            ],
            dtype=float,
        )

        class_idx = int(self.model.predict(features)[0])
        proba = self.model.predict_proba(features)[0]

        feature_names = [
            "Lines of Code",
            "Loop Count",
            "Condition Count",
            "Variable Count",
            "Nesting Depth",
            "Function Count",
        ]
        importances = {
            name: round(float(imp), 3)
            for name, imp in zip(feature_names, self.model.feature_importances_)
        }

        return {
            "class_index": class_idx,
            "label": _LABEL_MAP[class_idx],
            "color": _LABEL_COLORS[class_idx],
            "probability_low": round(float(proba[0]) * 100, 1),
            "probability_medium": round(float(proba[1]) * 100, 1),
            "probability_high": round(float(proba[2]) * 100, 1),
            "feature_importances": importances,
        }


# ── Module-level singleton ────────────────────────────────────────────────────
_classifier = None


def get_classifier() -> RiskClassifier:
    """Return the singleton classifier (lazy-loaded)."""
    global _classifier
    if _classifier is None:
        _classifier = RiskClassifier()
    return _classifier


def predict_risk(metrics: Dict) -> Dict:
    """Convenience function — predict risk from parsed code metrics."""
    return get_classifier().predict(metrics)