#!/usr/bin/env python3
"""Simplified MVAD test to determine output format."""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta, timezone
from anomaly_detector import MultivariateAnomalyDetector

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
    periods=60,  # Need at least sliding_window (50) samples
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
print("RESULTS TYPE:", type(results))
print("="*80)

if isinstance(results, dict):
    print("\nKEYS:", list(results.keys()))
    print("\nDETAILED STRUCTURE:")
    for key, value in results.items():
        print(f"\n  {key}:")
        print(f"    Type: {type(value)}")
        if isinstance(value, (list, tuple, np.ndarray)):
            print(f"    Length: {len(value)}")
            print(f"    Sample: {value[:3] if len(value) > 3 else value}")
        elif isinstance(value, dict):
            print(f"    Sub-keys: {list(value.keys())}")
            for sk, sv in value.items():
                print(f"      {sk}: {type(sv)} = {sv if not isinstance(sv, (list, np.ndarray)) or len(str(sv)) < 100 else str(sv)[:100]+'...'}")
        else:
            print(f"    Value: {value}")
else:
    print("\nRESULTS (not a dict):", results)

print("\n" + "="*80)
print("DONE")
print("="*80)
