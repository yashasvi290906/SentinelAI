import numpy as np
from collections import defaultdict, Counter
from functools import lru_cache
import logging

logger = logging.getLogger(__name__)


# =========================
# Attack classes (canonical order)
# =========================
ATTACK_CLASSES = ["DDoS", "DoS", "PortScan", "Bot", "WebAttack", "BruteForce", "Infiltration"]
ATTACK_TO_IDX = {name: i for i, name in enumerate(ATTACK_CLASSES)}

# Weights for severity calculation
ATTACK_WEIGHTS = {
    "DDoS": 0.95,
    "DoS": 0.80,
    "PortScan": 0.55,
    "Bot": 0.65,
    "WebAttack": 0.75,
    "BruteForce": 0.70,
    "Infiltration": 0.90,
}

# Model version
MODEL_VERSION = "v2.1-rule-based"


# =========================
# Rule-Based Prediction Engine
# =========================
TRAINING_SEQUENCES = [
    ["DDoS", "DDoS", "PortScan", "Bot", "WebAttack"],
    ["PortScan", "PortScan", "DDoS", "DDoS", "DoS"],
    ["Bot", "WebAttack", "BruteForce", "Infiltration"],
    ["DoS", "DoS", "DDoS", "PortScan", "Bot"],
    ["WebAttack", "BruteForce", "Infiltration", "DDoS"],
    ["PortScan", "Bot", "Bot", "WebAttack", "BruteForce"],
    ["DDoS", "PortScan", "WebAttack", "DoS", "DDoS"],
    ["BruteForce", "Infiltration", "DDoS", "PortScan", "Bot"],
    ["Infiltration", "DDoS", "DDoS", "DoS", "PortScan"],
    ["Bot", "Bot", "PortScan", "DDoS", "WebAttack"],
    ["DoS", "DDoS", "DDoS", "PortScan", "BruteForce"],
    ["WebAttack", "WebAttack", "BruteForce", "Infiltration", "DDoS"],
    ["PortScan", "DDoS", "DoS", "DoS", "PortScan"],
    ["DDoS", "DoS", "PortScan", "Bot", "Infiltration"],
    ["BruteForce", "WebAttack", "Bot", "PortScan", "DDoS"],
    ["Infiltration", "PortScan", "WebAttack", "BruteForce", "DDoS"],
    ["DDoS", "DDoS", "DDoS", "PortScan", "Bot"],
    ["DoS", "PortScan", "Bot", "WebAttack", "DoS"],
    ["Bot", "PortScan", "DDoS", "DoS", "PortScan"],
    ["WebAttack", "DoS", "DDoS", "DDoS", "BruteForce"],
]


class RuleBasedPredictor:
    """Transition frequency table from training sequences. Rule-based prediction engine."""

    def __init__(self):
        self.n_classes = len(ATTACK_CLASSES)
        self.transitions = {}
        self._build_model()

    def _build_model(self):
        for seq in TRAINING_SEQUENCES:
            encoded = [ATTACK_TO_IDX.get(a, 0) for a in seq]
            for ctx_len in range(1, min(5, len(encoded))):
                for i in range(ctx_len, len(encoded)):
                    context = tuple(encoded[i - ctx_len:i])
                    next_val = encoded[i]
                    if ctx_len not in self.transitions:
                        self.transitions[ctx_len] = defaultdict(Counter)
                    self.transitions[ctx_len][context][next_val] += 1

    def predict(self, X):
        results = []
        for row in X:
            seq = list(row)
            pred = self._predict_single(seq)
            results.append(pred)
        return np.array(results)

    def _predict_single(self, seq):
        for ctx_len in range(min(4, len(seq)), 0, -1):
            context = tuple(seq[-ctx_len:])
            if ctx_len in self.transitions and context in self.transitions[ctx_len]:
                counter = self.transitions[ctx_len][context]
                best = max(counter.items(), key=lambda x: (x[1], -x[0]))
                return best[0]

        all_classes = Counter()
        for seq in TRAINING_SEQUENCES:
            for a in seq:
                all_classes[ATTACK_TO_IDX.get(a, 0)] += 1
        return all_classes.most_common(1)[0][0]

    def predict_proba(self, X):
        results = []
        for row in X:
            seq = list(row)
            proba = self._predict_proba_single(seq)
            results.append(proba)
        return np.array(results)

    def _predict_proba_single(self, seq):
        proba = np.zeros(self.n_classes)

        for ctx_len in range(min(4, len(seq)), 0, -1):
            context = tuple(seq[-ctx_len:])
            if ctx_len in self.transitions and context in self.transitions[ctx_len]:
                counter = self.transitions[ctx_len][context]
                total = sum(counter.values())
                for cls, count in counter.items():
                    proba[cls] = count / total
                return proba

        proba[:] = 1.0 / self.n_classes
        return proba


class MockEncoder:
    def __init__(self):
        self.classes_ = np.array(ATTACK_CLASSES)

    def inverse_transform(self, y):
        return [self.classes_[min(i, len(self.classes_) - 1)] for i in y]


# =========================
# Markov Model (moved here to avoid circular import)
# =========================
class MarkovModel:
    def __init__(self):
        self.transitions = defaultdict(Counter)
        self.probabilities = {}

    def fit(self, sequence):
        for i in range(len(sequence) - 1):
            self.transitions[sequence[i]][sequence[i + 1]] += 1

        for state, next_states in self.transitions.items():
            total = sum(next_states.values())
            self.probabilities[state] = {
                k: v / total for k, v in next_states.items()
            }

    def predict(self, current_state):
        if current_state not in self.probabilities:
            return None, 0.0

        probs = self.probabilities[current_state]
        best = max(probs, key=probs.get)
        confidence = probs[best]
        return best, confidence


# =========================
# Build model (ONCE at startup)
# =========================
model = RuleBasedPredictor()
le = MockEncoder()


# =========================
# Markov Model
# =========================
sample_stream = [
    "DDoS", "DDoS", "PortScan", "Bot", "WebAttack",
    "BruteForce", "DoS", "DoS", "PortScan",
    "DDoS", "PortScan", "Bot", "Infiltration",
    "WebAttack", "BruteForce", "DDoS", "DoS",
]

markov = MarkovModel()
markov.fit(sample_stream)
