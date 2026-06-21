"""
Anomaly Detection Engine for SentinelAI.
Uses Isolation Forest, Z-score, and IQR methods to detect anomalous behavior.
Extracts features from parsed log events and scores them.
"""
import math
from collections import defaultdict, Counter
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass, field, asdict


@dataclass
class AnomalyResult:
    """Result of anomaly detection."""
    anomaly_score: float       # 0.0 to 1.0 (1.0 = most anomalous)
    risk_level: str            # LOW, MEDIUM, HIGH, CRITICAL
    anomalies: List[Dict[str, Any]] = field(default_factory=list)
    feature_scores: Dict[str, float] = field(default_factory=dict)
    explanation: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class IsolationForest:
    """
    Lightweight Isolation Forest implementation.
    No sklearn dependency - pure Python for portability.
    """
    
    def __init__(self, n_trees: int = 100, sample_size: int = 256):
        self.n_trees = n_trees
        self.sample_size = sample_size
        self.trees: List[Dict] = []
        self._fitted = False
    
    def fit(self, data: List[List[float]]):
        """Build isolation trees from training data."""
        if not data or not data[0]:
            return
        
        n_samples = len(data)
        self.trees = []
        
        for _ in range(self.n_trees):
            indices = list(range(n_samples))
            if n_samples > self.sample_size:
                import random
                indices = random.sample(range(n_samples), self.sample_size)
            
            subsample = [data[i] for i in indices]
            tree = self._build_tree(subsample, 0, int(math.ceil(math.log2(self.sample_size))))
            self.trees.append(tree)
        
        self._fitted = True
        self._n_samples = n_samples
    
    def _build_tree(self, data: List[List[float]], depth: int, max_depth: int) -> Dict:
        """Recursively build an isolation tree."""
        if len(data) <= 1 or depth >= max_depth:
            return {'type': 'leaf', 'size': len(data)}
        
        n_features = len(data[0])
        import random
        feature_idx = random.randint(0, n_features - 1)
        
        values = [row[feature_idx] for row in data]
        min_val, max_val = min(values), max(values)
        
        if min_val == max_val:
            return {'type': 'leaf', 'size': len(data)}
        
        split_val = random.uniform(min_val, max_val)
        
        left = [row for row in data if row[feature_idx] < split_val]
        right = [row for row in data if row[feature_idx] >= split_val]
        
        return {
            'type': 'internal',
            'feature': feature_idx,
            'threshold': split_val,
            'left': self._build_tree(left, depth + 1, max_depth),
            'right': self._build_tree(right, depth + 1, max_depth),
        }
    
    def score(self, sample: List[float]) -> float:
        """Score a sample. Higher = more anomalous."""
        if not self._fitted or not self.trees:
            return 0.5
        
        total_path = 0
        for tree in self.trees:
            total_path += self._path_length(tree, sample, 0)
        
        avg_path = total_path / len(self.trees)
        
        c = self._average_path_length(self.sample_size)
        if c == 0:
            return 0.5
        
        score = 2 ** (-avg_path / c)
        return min(1.0, max(0.0, score))
    
    def _path_length(self, node: Dict, sample: List[float], depth: int) -> float:
        """Calculate path length for a sample in a tree."""
        if node['type'] == 'leaf':
            return depth + self._average_path_length(node['size'])
        
        if sample[node['feature']] < node['threshold']:
            return self._path_length(node['left'], sample, depth + 1)
        else:
            return self._path_length(node['right'], sample, depth + 1)
    
    def _average_path_length(self, n: int) -> float:
        """Average path length of unsuccessful search in BST."""
        if n <= 1:
            return 0
        return 2.0 * (math.log(n - 1) + 0.5772156649) - (2.0 * (n - 1) / n)


class AnomalyDetector:
    """Real anomaly detection on log event features."""
    
    def __init__(self):
        self._ip_stats: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))
        self._global_stats: Dict[str, List[float]] = defaultdict(list)
        self._isolation_forest = IsolationForest(n_trees=50, sample_size=128)
        self._baseline: Optional[Dict[str, float]] = None
        self._events_processed = 0
        self._training_buffer: List[List[float]] = []
    
    def extract_features(self, events: List[Dict[str, Any]]) -> Dict[str, List[float]]:
        """Extract numerical features from events for anomaly detection."""
        features = {
            'request_rate': [],
            'unique_src_ips': [],
            'unique_dst_ports': [],
            'failed_auth_rate': [],
            'error_rate': [],
            'bytes_per_request': [],
            'unique_users': [],
            'event_diversity': [],
            'ip_entropy': [],
            'port_entropy': [],
        }
        
        if not events:
            return features
        
        windows: Dict[str, List[Dict]] = defaultdict(list)
        for event in events:
            ts = event.get('timestamp', '')
            if ts:
                try:
                    dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                    window_key = dt.strftime('%Y-%m-%d %H:%M')
                    windows[window_key].append(event)
                except (ValueError, TypeError):
                    continue
        
        for window_key, window_events in sorted(windows.items()):
            src_ips = set()
            dst_ports = set()
            users = set()
            event_types = set()
            total_bytes = 0
            errors = 0
            failed_auths = 0
            total = len(window_events)
            
            for event in window_events:
                src_ips.add(event.get('source_ip', ''))
                if event.get('dest_port'):
                    dst_ports.add(event['dest_port'])
                users.add(event.get('user', ''))
                event_types.add(event.get('event_type', ''))
                total_bytes += event.get('bytes_transferred', 0)
                
                status = event.get('status_code', 0)
                if status >= 400:
                    errors += 1
                if event.get('event_type') in ('brute_force', 'suspicious_auth') or status in (401, 403):
                    failed_auths += 1
            
            features['request_rate'].append(total)
            features['unique_src_ips'].append(len(src_ips))
            features['unique_dst_ports'].append(len(dst_ports))
            features['failed_auth_rate'].append(failed_auths / max(total, 1))
            features['error_rate'].append(errors / max(total, 1))
            features['bytes_per_request'].append(total_bytes / max(total, 1))
            features['unique_users'].append(len(users))
            features['event_diversity'].append(len(event_types))
            
            features['ip_entropy'].append(self._entropy(src_ips, window_events, 'source_ip'))
            features['port_entropy'].append(self._entropy(dst_ports, window_events, 'dest_port'))
        
        return features
    
    def _entropy(self, unique_set: set, events: List[Dict], field: str) -> float:
        """Calculate Shannon entropy of field distribution."""
        if not events:
            return 0.0
        
        counter = Counter()
        for event in events:
            val = event.get(field, '')
            if val:
                counter[str(val)] += 1
        
        total = sum(counter.values())
        if total == 0:
            return 0.0
        
        entropy = 0.0
        for count in counter.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def detect(self, events: List[Dict[str, Any]]) -> AnomalyResult:
        """Run anomaly detection on events."""
        if not events:
            return AnomalyResult(anomaly_score=0.0, risk_level='LOW', explanation='No events to analyze')
        
        features = self.extract_features(events)
        
        feature_vector = self._features_to_vector(features)
        self._training_buffer.extend(feature_vector)
        self._events_processed += len(events)
        
        if len(self._training_buffer) >= 50 and not self._isolation_forest._fitted:
            self._isolation_forest.fit(self._training_buffer)
        
        feature_scores = {}
        anomalies = []
        
        for feat_name, values in features.items():
            if not values:
                continue
            
            mean = sum(values) / len(values)
            std = (sum((x - mean) ** 2 for x in values) / len(values)) ** 0.5
            
            if std == 0:
                feature_scores[feat_name] = 0.0
                continue
            
            z_scores = [(v - mean) / std for v in values]
            max_z = max(abs(z) for z in z_scores)
            
            sorted_vals = sorted(values)
            q1 = sorted_vals[len(sorted_vals) // 4]
            q3 = sorted_vals[3 * len(sorted_vals) // 4]
            iqr = q3 - q1
            
            outliers = []
            for i, v in enumerate(values):
                if v < q1 - 1.5 * iqr or v > q3 + 1.5 * iqr:
                    outliers.append((i, v))
            
            z_score_norm = min(max_z / 3.0, 1.0)
            outlier_ratio = len(outliers) / max(len(values), 1)
            feature_score = 0.6 * z_score_norm + 0.4 * outlier_ratio
            
            feature_scores[feat_name] = feature_score
            
            if feature_score > 0.5:
                anomalies.append({
                    'feature': feat_name,
                    'score': round(feature_score, 3),
                    'mean': round(mean, 2),
                    'std': round(std, 2),
                    'max_z_score': round(max_z, 2),
                    'outlier_count': len(outliers),
                    'description': self._describe_anomaly(feat_name, mean, std, max_z, len(outliers)),
                })
        
        if feature_scores:
            overall_score = sum(feature_scores.values()) / len(feature_scores)
        else:
            overall_score = 0.0
        
        if self._isolation_forest._fitted and feature_vector:
            iforest_scores = [self._isolation_forest.score(vec) for vec in feature_vector[:10]]
            iforest_avg = sum(iforest_scores) / len(iforest_scores) if iforest_scores else 0
            overall_score = 0.6 * overall_score + 0.4 * iforest_avg
        
        risk_level = self._score_to_risk(overall_score)
        
        explanation = self._generate_explanation(overall_score, risk_level, anomalies, features)
        
        return AnomalyResult(
            anomaly_score=round(overall_score, 3),
            risk_level=risk_level,
            anomalies=anomalies,
            feature_scores={k: round(v, 3) for k, v in feature_scores.items()},
            explanation=explanation,
        )
    
    def _features_to_vector(self, features: Dict[str, List[float]]) -> List[List[float]]:
        """Convert feature dict to list of vectors."""
        vectors = []
        max_len = max((len(v) for v in features.values()), default=0)
        
        for i in range(max_len):
            vector = []
            for feat_name in sorted(features.keys()):
                vals = features[feat_name]
                vector.append(vals[i] if i < len(vals) else 0.0)
            vectors.append(vector)
        
        return vectors
    
    def _describe_anomaly(self, feature: str, mean: float, std: float, max_z: float, n_outliers: int) -> str:
        """Generate human-readable anomaly description."""
        descriptions = {
            'request_rate': f"Request rate spiked to {max_z:.1f}σ above mean ({mean:.1f} ± {std:.1f})",
            'unique_src_ips': f"Unusual diversity of source IPs detected ({n_outliers} outlier windows)",
            'unique_dst_ports': f"Abnormal port access pattern ({n_outliers} outlier windows)",
            'failed_auth_rate': f"Failed authentication rate elevated to {max_z:.1f}σ above baseline",
            'error_rate': f"Error response rate unusually high ({max_z:.1f}σ)",
            'bytes_per_request': f"Data transfer volume anomalous ({max_z:.1f}σ from norm)",
            'unique_users': f"Unexpected number of unique users ({n_outliers} outlier windows)",
            'event_diversity': f"Unusual variety of event types ({n_outliers} outlier windows)",
            'ip_entropy': f"IP distribution entropy changed ({max_z:.1f}σ from baseline)",
            'port_entropy': f"Port distribution entropy changed ({max_z:.1f}σ from baseline)",
        }
        return descriptions.get(feature, f"Anomaly detected in {feature} ({max_z:.1f}σ)")
    
    def _score_to_risk(self, score: float) -> str:
        """Map anomaly score to risk level."""
        if score >= 0.8:
            return 'CRITICAL'
        elif score >= 0.6:
            return 'HIGH'
        elif score >= 0.4:
            return 'MEDIUM'
        elif score >= 0.2:
            return 'LOW'
        return 'INFO'
    
    def _generate_explanation(self, score: float, risk: str, anomalies: List[Dict], features: Dict) -> str:
        """Generate natural language explanation."""
        if not anomalies:
            return f"Anomaly score: {score:.2f} ({risk}). No significant anomalies detected in the analyzed events."
        
        top_anomalies = sorted(anomalies, key=lambda x: x['score'], reverse=True)[:3]
        descriptions = [a['description'] for a in top_anomalies]
        
        return (
            f"Anomaly Score: {score:.2f} ({risk}). "
            f"Detected {len(anomalies)} anomalous features. "
            f"Key findings: {'; '.join(descriptions)}"
        )


# Singleton
anomaly_detector = AnomalyDetector()
