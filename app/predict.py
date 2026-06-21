import numpy as np
from collections import defaultdict, Counter


ATTACK_CLASSES = ["DDoS", "DoS", "PortScan", "Bot", "WebAttack", "BruteForce", "Infiltration"]
ATTACK_TO_IDX = {name: i for i, name in enumerate(ATTACK_CLASSES)}


# =========================
# ML Prediction with Top-3 + Explanation
# =========================
def predict_next(seq, model, le):
    """
    Predict next attack label using ML model.
    Returns: (prediction_label, confidence, top_3, explanation)
    """
    seq_arr = np.array(seq).reshape(1, -1)

    pred = model.predict(seq_arr)[0]

    # Get probability distribution
    if hasattr(model, 'predict_proba'):
        proba = model.predict_proba(seq_arr)[0]
        confidence = float(np.max(proba))

        # Top-3 predictions
        top_indices = np.argsort(proba)[::-1][:3]
        top_3 = [
            {"attack": le.inverse_transform([i])[0], "probability": round(float(proba[i]), 4)}
            for i in top_indices
            if proba[i] > 0
        ]

        # Build explanation
        explanation = _build_explanation(seq, le.inverse_transform([pred])[0], confidence, proba, model, le)
    else:
        confidence = 0.5
        top_3 = [{"attack": le.inverse_transform([pred])[0], "probability": 0.5}]
        explanation = {"reasoning": ["Model did not provide probability distribution."], "pattern_match": "N/A", "similar_sequences": 0, "input_pattern": ""}

    label = le.inverse_transform([pred])[0]
    return label, confidence, top_3, explanation


def _build_explanation(seq, prediction, confidence, proba, model, le):
    """Build human-readable explanation for prediction."""
    attack_names = le.inverse_transform(seq)
    reasoning_parts = []

    # Pattern analysis
    freq = Counter(attack_names)
    most_common = freq.most_common(1)[0]
    if most_common[1] > 1:
        reasoning_parts.append(f"Repeated {most_common[0]} pattern detected ({most_common[1]}x)")

    # Sequence trend
    if len(seq) >= 2:
        last_two = attack_names[-2:]
        if last_two[0] == last_two[1]:
            reasoning_parts.append(f"Escalating {last_two[0]} sequence")
        else:
            reasoning_parts.append(f"Transition from {last_two[0]} to potential {prediction}")

    # Transition probability
    transition_prob = float(max(proba))
    reasoning_parts.append(f"ML transition probability: {transition_prob:.1%}")

    # Confidence assessment
    if confidence >= 0.85:
        reasoning_parts.append("High confidence match against training patterns")
    elif confidence >= 0.65:
        reasoning_parts.append("Moderate confidence — pattern partially matches training data")
    else:
        reasoning_parts.append("Low confidence — sequence not well represented in training data")

    # Similar sequences from training
    similar_count = _count_similar_sequences(seq)
    reasoning_parts.append(f"Similar training sequences found: {similar_count}")

    return {
        "reasoning": reasoning_parts,
        "pattern_match": f"{confidence:.1%}",
        "similar_sequences": similar_count,
        "input_pattern": " → ".join(attack_names),
    }


def _count_similar_sequences(seq):
    """Count how many training sequences share the same last N attacks."""
    from model_loader import TRAINING_SEQUENCES
    count = 0
    window = min(3, len(seq))
    target = tuple(seq[-window:])
    for train_seq in TRAINING_SEQUENCES:
        encoded = [ATTACK_TO_IDX.get(a, 0) for a in train_seq]
        if tuple(encoded[-window:]) == target:
            count += 1
    return count


# =========================
# Import MarkovModel from model_loader (single source)
# =========================
from model_loader import MarkovModel


# =========================
# Wrapper for FastAPI
# =========================
def markov_predict(current, markov_model):
    return markov_model.predict(current)
