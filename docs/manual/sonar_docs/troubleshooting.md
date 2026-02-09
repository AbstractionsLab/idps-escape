# SONAR troubleshooting guide

Solutions for common issues and errors in SONAR.

## Quick diagnostics

```bash
# 1. Check Wazuh connection
poetry run sonar check

# 2. Verify Python environment
poetry run python --version  # Should be 3.10.12

# 3. Check dependencies
poetry install --with sonar

# 4. Test with debug mode
poetry run sonar train --debug
```

## Connection issues

### Error: Connection refused

```
requests.exceptions.ConnectionError: Connection refused
```

**Causes:**
- Wazuh/OpenSearch not running
- Incorrect URL in configuration
- Network/firewall issues

**Solutions:**

```bash
# 1. Check Wazuh is running
curl -u admin:admin https://localhost:9200/_cluster/health

# 2. Verify configuration
cat default_config.yaml | grep base_url

# 3. Use debug mode for development
poetry run sonar train --debug
```

### Error: SSL verification failed

```
requests.exceptions.SSLError: SSL verification failed
```

**Solution:**

Disable SSL verification in configuration:

```yaml
wazuh:
  verify_ssl: false
```

### Error: Authentication failed

```
401 Unauthorized
```

**Solutions:**

```bash
# 1. Check credentials
cat default_config.yaml | grep -A2 "username"

# 2. Test with curl
curl -u admin:admin https://localhost:9200/

# 3. Update configuration
vim default_config.yaml  # Update username/password
```

## Training issues

### Error: No alerts found

```
WARNING: Retrieved 0 alerts. Cannot train with empty data.
```

**Causes:**
- Time range too narrow
- Query filter too restrictive
- No matching alerts in Wazuh

**Solutions:**

```bash
# 1. Extend lookback period
poetry run sonar train --lookback-hours 168  # 1 week instead of 24h

# 2. Check alert count in Wazuh
curl -u admin:admin "https://localhost:9200/wazuh-alerts-*/_count"

# 3. Remove or adjust query_filter in scenario
```

**Scenario fix:**

```yaml
training:
  lookback_hours: 168  # Increase from 24
  # Remove restrictive query_filter temporarily
```

### Error: Insufficient data for sliding window

```
ValueError: Insufficient data points (50) for sliding window (200)
```

**Cause:** Not enough time buckets for the configured sliding window.

**Solutions:**

```yaml
training:
  sliding_window: 50  # Reduce from 200
  # OR
  lookback_hours: 168  # Increase to get more data
  # OR
  bucket_minutes: 10  # Increase bucket size (fewer buckets)
```

### Error: Feature mismatch

```
ValueError: Training produced 14 features, detection has 17 features
```

**Status:** ✅ **Automatically handled in SONAR**

SONAR includes automatic column alignment:
- Adds missing columns (filled with 0)
- Removes extra columns
- Reorders to match training

**No action needed** - this error should not occur. If it does:

```bash
# 1. Check for version issues (from project root)
cd /home/alab/soar
git log -1 sonar/engine.py | head -5

# 2. Retrain model
rm model/mvad_model.pkl
poetry run sonar train --lookback-hours 24

# 3. Verify alignment in logs
poetry run sonar detect --lookback-minutes 10  # Check for "Aligning columns" message
```

### Error: Data format not recognized (debug mode)

```
ValueError: Unexpected JSON type in test_data.json
```

**Cause**: Invalid JSON format or unsupported structure in debug mode.

**Solutions**:

```bash
# 1. Validate JSON syntax
jq . test_data.json  # Should pretty-print without errors

# 2. Check supported formats
# LocalDataProvider accepts:
# - JSON array: [{...}, {...}]
# - Single object: {...}
# - OpenSearch response: {hits: {hits: [{_source: {...}}]}}

# 3. If using OpenSearch export, ensure it has the hits structure
cat test_data.json | jq '.hits.hits[0]._source' | head

# 4. Convert array to OpenSearch format if needed
cat array.json | jq '{hits: {hits: [.[] | {_source: .}]}}' > opensearch_format.json
```

### Warning: Query filter returns no results

```
WARNING: Query filter returned 0 alerts. Check filter syntax.
```

**Cause**: OpenSearch query filter in scenario is too restrictive.

**Solutions**:

```yaml
# 1. Test query filter directly in OpenSearch
# Use Wazuh Dev Tools or curl:
GET wazuh-alerts-*/_search
{
  "query": {
    "bool": {
      "must": [{"match": {"rule.groups": "authentication"}}]
    }
  },
  "size": 0
}
# Check "hits.total.value" - should be > 0

# 2. Simplify filter temporarily
query_filter:
  match_all: {}  # Remove all filters to test

# 3. Use should instead of must for broader matching
query_filter:
  bool:
    should:  # At least one must match (OR logic)
      - match: {"rule.groups": "authentication"}
      - match: {"rule.groups": "sudo"}
    minimum_should_match: 1

# 4. Check field names match your alert structure
# View sample alert:
GET wazuh-alerts-*/_search
{"size": 1, "sort": [{"@timestamp": "desc"}]}
```

### Error: Memory exhausted

```
MemoryError: Unable to allocate array
```

**Causes:**
- Too many features (high cardinality categorical fields)
- Large sliding window with high-frequency buckets

**Solutions:**

```yaml
training:
  # Reduce categorical feature cardinality
  categorical_top_k: 5  # Reduce from 10

  # Use fewer categorical fields
  categorical_fields:
    - "agent.id"  # Remove others temporarily

  # Increase bucket size
  bucket_minutes: 10  # Increase from 5

  # Reduce sliding window
  sliding_window: 100  # Reduce from 200
```

### Error: Model name conflict

```
FileExistsError: Model file already exists: ./models/my_model_v1.pkl
```

**Cause**: Attempting to overwrite existing model with same name.

**Solutions**:

```bash
# 1. Use versioned model names in scenario
model_name: "my_model_v2_20260125"  # Include version and date

# 2. Remove old model if intentional overwrite
rm ./models/my_model_v1.pkl
poetry run sonar train --scenario my_scenario.yaml

# 3. Use auto-generated names (omit model_name)
# SONAR generates unique names with timestamps

# 4. Organize by environment
model_name: "brute_force_production_baseline"
model_name: "brute_force_staging_baseline"
```

### Warning: Shipping disabled in debug mode

```
INFO: Shipping disabled because debug mode is active
```

**Cause**: This is **intentional behavior** - debug mode automatically disables shipping as a safety measure.

**Explanation**: Prevents accidental indexing of synthetic test data to production data streams.

**Solutions**:

```bash
# 1. For production shipping, remove --debug flag
poetry run sonar train --scenario my_scenario.yaml --ship
# NOT: poetry run sonar train --scenario my_scenario.yaml --ship --debug

# 2. Test shipping setup without actually indexing
poetry run sonar train --scenario my_scenario.yaml --ship --dry-run

# 3. If you need to test shipping with local data:
# - Configure wazuh connection to test instance in config.yaml
# - Use real Wazuh connection (not --debug)
# - Point to test cluster, not production
```

### Info: Fewer features than expected (derived_features)

```
INFO: Training on 5 features (expected more with derived_features=true)
```

**Possible causes**:
1. Derived features module not fully implemented yet
2. Insufficient data for pattern detection
3. Feature builder configuration

**Solutions**:

```yaml
# 1. Verify derived_features is enabled
training:
  derived_features: true  # Should be in training section

# 2. Check if sufficient alerts for pattern detection
# Derived features need minimum alert volume:
# - At least 100+ alerts per bucket for diversity metrics
# - Multiple agents/sources for cardinality features

# 3. Explicitly disable if not needed
training:
  derived_features: false  # Use only raw numeric fields

# 4. Check feature builder logs for details
poetry run sonar train --scenario my_scenario.yaml 2>&1 | grep -i "feature"
```

## Detection issues

### Error: Model not found

```
FileNotFoundError: Model file not found: ./model/mvad_model.pkl
```

**Cause:** Detection requires a trained model.

**Solutions:**

```bash
# 1. Train model first
poetry run sonar train --lookback-hours 24

# 2. Or use scenario with training section
poetry run sonar scenario --use-case scenarios/brute_force_detection.yaml

# 3. Check model file exists
ls -lh model/mvad_model.pkl
```

### Error: No anomalies detected

```
INFO: Detection complete. Found 0 anomalies.
```

**Not an error** - means no anomalous patterns detected.

**If unexpected:**

```yaml
# Lower threshold for more sensitive detection
detection:
  threshold: 0.5  # Reduce from 0.7

# Extend lookback period
detection:
  lookback_minutes: 120  # Increase from 60
```

### Error: All points marked as anomalies

```
WARNING: Detection marked 150/150 points as anomalies
```

**Causes:**
- Model not properly trained
- Threshold too low
- Data distribution mismatch

**Solutions:**

```bash
# 1. Retrain with more data
poetry run sonar train --lookback-hours 168

# 2. Increase threshold
```

```yaml
detection:
  threshold: 0.85  # Increase from 0.7
```

```bash
# 3. Check training data quality
poetry run sonar train --debug  # Use known-good test data
```

## Data quality issues

### Error: Invalid timestamp format

```
ValueError: Cannot parse timestamp: 2025-12-29T10:00:00
```

**Cause:** Timestamp missing timezone info.

**Solution:** Timestamps must be ISO 8601 format with timezone:

```json
{
  "timestamp": "2025-12-29T10:00:00.000Z"  // Correct
  "timestamp": "2025-12-29T10:00:00"       // Missing .000Z
}
```

For test data, use proper format:

```python
from datetime import datetime, timezone
timestamp = datetime.now(timezone.utc).isoformat()
```

### Error: NaN values in features

```
WARNING: Found NaN values in features, filling with 0
```

**Not fatal** - SONAR automatically handles NaN values.

**To prevent:**

```yaml
training:
  # Only use fields that always exist
  numeric_fields:
    - "rule.level"  # Always present
    # Remove optional fields like "data.cpu_usage_%" if not always present
```

### Error: Non-numeric column

```
ValueError: Column 'rule.description' is not numeric
```

**Cause:** Specified a text field as numeric.

**Solution:**

```yaml
training:
  numeric_fields:
    - "rule.level"  # Numeric
    # - "rule.description"  # Remove - this is text

  categorical_fields:
    - "rule.description"  # Use as categorical instead (if needed)
```

## Configuration issues

### Error: Configuration file not found

```
FileNotFoundError: default_config.yaml not found
```

**Solutions:**

```bash
# 1. Check working directory
pwd  # Should be /home/alab/soar

# 2. Use absolute path
poetry run sonar train --config /home/alab/soar/sonar/default_config.yaml

# 3. Create configuration
cp sonar/default_config.yaml my_config.yaml
```

### Error: Invalid YAML syntax

```
yaml.scanner.ScannerError: mapping values are not allowed here
```

**Cause:** YAML syntax error.

**Common mistakes:**

```yaml
# Incorrect indentation
training:
numeric_fields:
  - "rule.level"

# Correct indentation
training:
  numeric_fields:
    - "rule.level"

# Missing quotes around special characters
query_filter:
  match: {rule.groups: web}

# Quotes around field names
query_filter:
  match: {"rule.groups": "web"}
```

**Validation:**

```bash
# Check YAML syntax
poetry run python -c "import yaml; yaml.safe_load(open('scenario.yaml'))"
```

### Error: Missing required field

```
TypeError: UseCase.__init__() missing required keyword argument: 'name'
```

**Cause:** Scenario missing required field.

**Minimal valid scenario:**

```yaml
name: "My Scenario"
description: "What it does"
training:
  lookback_hours: 24
```

## Performance issues

### Issue: Training takes too long

**Causes:**
- Large sliding window
- Many features
- Large dataset

**Solutions:**

```yaml
training:
  sliding_window: 100  # Reduce from 300
  bucket_minutes: 10   # Increase from 5
  categorical_top_k: 5  # Reduce from 10
```

**Benchmark:** Training should complete in < 5 minutes for typical workloads.

### Issue: High memory usage

**Solutions:**

```yaml
training:
  # Reduce feature count
  categorical_fields: []  # Start with none

  # Use larger buckets
  bucket_minutes: 15

  # Shorter lookback
  lookback_hours: 24  # Instead of 168
```

**Monitor:**

```bash
# Watch memory during training
watch -n 1 'ps aux | grep sonar'
```

## Debug mode issues

### Error: Test data file not found

```
FileNotFoundError: test_data/synthetic_alerts/normal_baseline.json not found
```

**Solutions:**

```bash
# 1. Check file exists
ls sonar/test_data/synthetic_alerts/

# 2. Generate test data
poetry run python sonar/test_data/generate_resource_data.py

# 3. Update configuration
vim default_config.yaml  # Fix data_dir path
```

### Error: Test data has wrong format

```
ValueError: Expected array of alerts, got single object
```

**Cause:** Test data must be JSON array:

```json
// Correct format
[
  {"timestamp": "...", "rule": {...}},
  {"timestamp": "...", "rule": {...}}
]

// Wrong format
{"timestamp": "...", "rule": {...}}
```

**Fix:**

```json
// Wrap single object in array
[
  {"timestamp": "...", "rule": {...}}
]
```

## Getting help

### Enable debug logging

```python
# Add to top of your script
import logging
logging.basicConfig(level=logging.DEBUG)
```

Or via environment variable:

```bash
export LOG_LEVEL=DEBUG
poetry run sonar train --lookback-hours 24
```

### Collect diagnostic information

```bash
# 1. System info
python --version
poetry --version
uname -a

# 2. SONAR version
cd /home/alab/soar
git log -1 --oneline sonar/

# 3. Configuration
cat default_config.yaml

# 4. Recent errors
poetry run sonar train --debug 2>&1 | tee debug.log
```

### Check test suite

```bash
# Run all tests
poetry run pytest tests/ -v

# Run specific test
poetry run pytest tests/engine_test.py -v

# Check for regressions
poetry run pytest tests/ --tb=short
```

### Common log messages

**Normal:**
```
INFO: Retrieved 1234 alerts
INFO: Built time series: shape=(200, 14)
INFO: Training complete
INFO: Detection complete. Found 3 anomalies.
```

**Warning (non-fatal):**
```
WARNING: Found NaN values, filling with 0
WARNING: Low sample count: 50 (recommended: 100+)
```

**Error (requires action):**
```
ERROR: Connection failed: Connection refused
ERROR: No alerts found in time range
ERROR: Model file not found
```

## Still stuck?

1. Check [setup-guide.md](./setup-guide.md) for installation verification
2. Review [scenario-guide.md](./scenario-guide.md) for usage patterns
3. See [architecture.md](./architecture.md) for system design
4. Examine test files in `tests/` for working examples
5. Run with debug mode: `--debug` flag uses local test data

## Known limitations

1. **Python version**: Requires exactly 3.10.12 (specified in pyproject.toml)
2. **MVAD device**: CPU only (GPU support available but not tested)
3. **Time bucket alignment**: Buckets aligned to epoch, not query time
4. **Categorical encoding**: High cardinality fields can cause memory issues
5. **Realtime mode**: Polling-based, not push-based (60s minimum interval)

## Error reference

| Error | Cause | Solution |
|-------|-------|----------|
| Connection refused | Wazuh not running | Start Wazuh or use `--debug` |
| 401 Unauthorized | Wrong credentials | Update config credentials |
| SSL verification failed | Self-signed cert | Set `verify_ssl: false` |
| No alerts found | Empty time range | Extend `lookback_hours` |
| Model not found | Train before detect | Run training first |
| Feature mismatch | Different categories | Automatic in v2 |
| Insufficient data | Small dataset | Reduce `sliding_window` |
| Memory error | Too many features | Reduce `categorical_top_k` |
| Invalid timestamp | Missing timezone | Use ISO 8601 with Z |
| YAML syntax error | Malformed YAML | Check indentation |
