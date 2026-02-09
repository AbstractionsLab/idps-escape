#!/usr/bin/env python3
"""Format MVAD results for analysis."""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta, timezone
from anomaly_detector import MultivariateAnomalyDetector
import json

# Create training data
np.random.seed(42)
timestamps = pd.date_range(
    start=datetime.now(timezone.utc) - timedelta(hours=24),
    periods=300,
    freq='5min'
)

data = pd.DataFrame({
    'feature_1': np.random.randn(300) * 10 + 50,
    'feature_2': np.random.randn(300) * 5 + 100,
}, index=timestamps)

# Create test data
test_timestamps = pd.date_range(
    start=timestamps[-1] + timedelta(minutes=5),
    periods=60,
    freq='5min'
)

test_data = pd.DataFrame({
    'feature_1': np.random.randn(60) * 10 + 50,
    'feature_2': np.random.randn(60) * 5 + 100,
}, index=test_timestamps)

# Inject anomaly
test_data.iloc[25:28, :] = test_data.iloc[25:28, :] * 3

print("Training model...")
model = MultivariateAnomalyDetector()
model.fit(data, params={'sliding_window': 50})

print("Running prediction...")
results = model.predict(data=test_data, context={})

print("\n" + "="*80)
print("MVAD PREDICTION RESULTS SCHEMA")
print("="*80)

print(f"\n1. RESULTS TYPE: {type(results)}")
print(f"2. RESULTS IS LIST: {isinstance(results, list)}")
print(f"3. NUMBER OF RESULTS: {len(results) if isinstance(results, list) else 'N/A'}")

if isinstance(results, list) and len(results) > 0:
    first_result = results[0]
    print(f"\n4. TYPE OF EACH RESULT ELEMENT: {type(first_result)}")
    
    if isinstance(first_result, dict):
        print("\n5. KEYS IN EACH RESULT DICT:")
        for key in first_result.keys():
            print(f"   - {key}")
        
        print("\n6. DETAILED SCHEMA OF FIRST RESULT:")
        for key, value in first_result.items():
            print(f"\n   '{key}':")
            print(f"      Type: {type(value)}")
            if isinstance(value, (list, tuple)):
                print(f"      Length: {len(value)}")
                if len(value) > 0:
                    print(f"      First element type: {type(value[0])}")
                    if isinstance(value[0], dict):
                        print(f"      First element keys: {list(value[0].keys())}")
            else:
                print(f"      Value: {value}")
        
        print("\n7. SAMPLE RESULT (pretty printed):")
        print(json.dumps({
            'index': str(first_result['index']),
            'is_anomaly': first_result['is_anomaly'],
            'score': first_result['score'],
            'severity': first_result['severity'],
            'interpretation': first_result['interpretation'][:1] if len(first_result['interpretation']) > 0 else []
        }, indent=2))
        
        # Find an anomaly if any
        anomalies = [r for r in results if r.get('is_anomaly', False)]
        print(f"\n8. NUMBER OF ANOMALIES DETECTED: {len(anomalies)}")
        
        if anomalies:
            print("\n9. SAMPLE ANOMALY RESULT:")
            print(json.dumps({
                'index': str(anomalies[0]['index']),
                'is_anomaly': anomalies[0]['is_anomaly'],
                'score': anomalies[0]['score'],
                'severity': anomalies[0]['severity'],
                'interpretation_count': len(anomalies[0]['interpretation'])
            }, indent=2))

print("\n" + "="*80)
print("SUMMARY OF MVAD RESULT FORMAT:")
print("="*80)
print("""
The predict() method returns a LIST of dictionaries, where each dictionary has:
  - 'index': pd.Timestamp - the timestamp for this prediction point
  - 'is_anomaly': bool - whether this point is anomalous
  - 'score': float - anomaly score (0.0 to 1.0)
  - 'severity': float - severity score (0.0 for normal, higher for anomalies)
  - 'interpretation': list of dicts - per-feature contribution analysis
      Each interpretation dict contains:
        - 'variable_name': str - feature name
        - 'contribution_score': float - how much this feature contributed
        - 'correlation_changes': dict - correlation change info

Length of results list = number of time points in prediction data.
""")
print("="*80)
