#!/usr/bin/env python3
"""
Test script to determine the exact output format of MVAD predict() method.
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta, timezone
from anomaly_detector import MultivariateAnomalyDetector
import json

print("=" * 80)
print("MVAD Library Output Format Test")
print("=" * 80)

# Create synthetic training data
np.random.seed(42)
timestamps = pd.date_range(
    start=datetime.now(timezone.utc) - timedelta(hours=24),
    periods=300,
    freq='5min'
)

# Create multivariate time series (3 features)
data = pd.DataFrame({
    'feature_1': np.random.randn(300) * 10 + 50,
    'feature_2': np.random.randn(300) * 5 + 100,
    'feature_3': np.random.randn(300) * 3 + 25,
}, index=timestamps)

# Add some anomalies to test data
test_timestamps = pd.date_range(
    start=timestamps[-1] + timedelta(minutes=5),
    periods=50,
    freq='5min'
)

test_data = pd.DataFrame({
    'feature_1': np.random.randn(50) * 10 + 50,
    'feature_2': np.random.randn(50) * 5 + 100,
    'feature_3': np.random.randn(50) * 3 + 25,
}, index=test_timestamps)

# Inject anomalies
test_data.iloc[10:15, :] = test_data.iloc[10:15, :] * 3
test_data.iloc[30:33, :] = test_data.iloc[30:33, :] * 2.5

print("\n1. Training data shape:", data.shape)
print("2. Test data shape:", test_data.shape)

# Initialize and train model
print("\n3. Training MVAD model...")
model = MultivariateAnomalyDetector()

params = {
    'sliding_window': 100,
}

model.fit(data, params=params)
print("   ✓ Training complete")

# Run prediction
print("\n4. Running prediction...")
# Try with context parameter
try:
    results = model.predict(data=test_data, context={})
    print("   ✓ Prediction complete (with context)")
except TypeError as e:
    print(f"   Failed with context: {e}")
    print("   Trying without context parameter...")
    try:
        results = model.predict(test_data)
        print("   ✓ Prediction complete (without context)")
    except Exception as e2:
        print(f"   Failed: {e2}")
        raise

# Analyze results structure
print("\n" + "=" * 80)
print("RESULTS ANALYSIS")
print("=" * 80)

print("\n5. Type of results:", type(results))
print("\n6. Results is dict:", isinstance(results, dict))

if isinstance(results, dict):
    print("\n7. Top-level keys in results:")
    for key in results.keys():
        print(f"   - {key}")
    
    print("\n8. Detailed structure of each key:")
    for key, value in results.items():
        print(f"\n   Key: '{key}'")
        print(f"   Type: {type(value)}")
        
        if isinstance(value, (list, tuple, np.ndarray)):
            print(f"   Length: {len(value)}")
            if len(value) > 0:
                print(f"   First element type: {type(value[0])}")
                print(f"   First 5 elements: {value[:5]}")
                print(f"   Last 5 elements: {value[-5:]}")
        elif isinstance(value, dict):
            print(f"   Sub-keys: {list(value.keys())}")
            for sub_key, sub_value in value.items():
                print(f"      - {sub_key}: {type(sub_value)}")
                if isinstance(sub_value, (list, tuple, np.ndarray)) and len(sub_value) <= 10:
                    print(f"        Value: {sub_value}")
                elif isinstance(sub_value, (int, float, bool, str)):
                    print(f"        Value: {sub_value}")
        else:
            print(f"   Value: {value}")

print("\n9. Full results as JSON (first attempt):")
try:
    # Try to convert to JSON-serializable format
    def make_serializable(obj):
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, dict):
            return {k: make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return [make_serializable(item) for item in obj]
        else:
            return obj
    
    serializable_results = make_serializable(results)
    print(json.dumps(serializable_results, indent=2, default=str))
except Exception as e:
    print(f"   Could not serialize to JSON: {e}")
    print("   Raw results:")
    print(results)

# Check for specific expected fields
print("\n10. Checking for expected fields:")
expected_fields = ['is_anomaly', 'scores', 'threshold', 'interpretation', 'severity']
for field in expected_fields:
    if isinstance(results, dict):
        has_field = field in results
        print(f"   - '{field}': {has_field}")
        if has_field:
            print(f"     Type: {type(results[field])}")
            if isinstance(results[field], dict):
                print(f"     Sub-keys: {list(results[field].keys())}")

print("\n" + "=" * 80)
print("TEST COMPLETE")
print("=" * 80)
