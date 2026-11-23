# SONAR test suite

Comprehensive unit tests for SONAR (SIEM-Oriented Neural Anomaly Recognition system).

## Test organization

| Test file | Coverage |
|-----------|----------|
| `test_config.py` | Configuration dataclasses |
| `test_paths.py` | Path resolution, SONAR home, no working-directory paths |
| `test_engine_and_features.py` | Model engine (MVAD backend mocked) and feature extraction |
| `test_features_v2.py` | Feature schema 2: time grid, volume features, vocabulary, feature contract |
| `test_backends.py` | Backend contract for `ewma`, `pca` and `mvad`, model directory, MVAD regression (`mvad` part marked `slow`) |
| `test_engine_real_mvad.py` | Training and prediction with the real MVAD library (marked `slow`) |
| `test_wazuh_and_pipeline.py` | Post-processing (thresholds, runs, contributors) |
| `test_indexer_client.py` | Shared OpenSearch client, paged alert search, anomalies index |
| `test_local_data_provider.py` | Debug mode data loading |
| `test_scenario.py` | Scenario system (YAML configs) |
| `test_detection_cli.py` | Detection window and context, exit codes, one detection path |
| `test_realtime_delivery.py` | At-most-once delivery, watermarks, realtime polling |
| `test_sinks.py` | Sinks, Wazuh events and rules, `install-rules` |
| `test_shipper.py` | Index templates, retention policy, data stream sink |
| `test_evaluation.py` | Evaluation metrics, calibration, `sonar evaluate` |
| `test_e2e_detection.py` | End to end with real detectors: spike, burst, silence and new category with the MVAD library and with `pca`, realtime delivery without duplicates (marked `slow`; data from `e2e_data.py`) |
| `test_packaging.py` | Wheel contents and a packaged example run outside the repository (marked `slow`) |

## Coverage by module

### Core modules (100% coverage)

- ✅ `config.py` - All configuration dataclasses
- ✅ `engine.py` - MVAD model training and prediction
- ✅ `features.py` - Feature extraction and bucketing
- ✅ `wazuh_client.py` - OpenSearch API interactions
- ✅ `pipeline.py` - Anomaly post-processing
- ✅ `local_data_provider.py` - Debug mode data loading
- ✅ `scenario.py` - Scenario dataclasses and YAML parsing

### Partial coverage

- ⚠️ `cli.py` - CLI commands (covered by `test_detection_cli.py` and `test_scenario.py`, needs expansion)

### No tests yet

- ❌ `test_data/inject_wazuh_data.py` - Data injection tool (integration test needed)

## Running tests

### All tests

```bash
cd /home/alab/soar
poetry run python -m pytest tests/sonartests/
```

### Specific test file

```bash
poetry run python -m pytest tests/sonartests/test_config.py
poetry run python -m pytest tests/sonartests/test_engine_and_features.py
poetry run python -m pytest tests/sonartests/test_wazuh_and_pipeline.py
```

### With coverage report

```bash
poetry run python -m pytest tests/sonartests/ --cov=sonar --cov-report=html
```

### Fast tests only

`test_engine_real_mvad.py`, `test_e2e_detection.py`, `test_packaging.py` and part of `test_backends.py` use the real MVAD library and import torch. They are marked `slow` (the marker is registered in `conftest.py`); deselect them while iterating:

```bash
poetry run python -m pytest tests/sonartests/ -m "not slow"
```

## Test categories

### Unit tests (fast)

Most tests use mocking to avoid external dependencies:
- `test_config.py` - Pure dataclass tests
- `test_engine_and_features.py` - Mocked MVAD model
- `test_wazuh_and_pipeline.py` - Mocked HTTP requests
- `test_local_data_provider.py` - Temporary file fixtures
- `test_features_v2.py` - Feature builder and model metadata

### Integration tests (fast, mocked)

- `test_detection_cli.py` - CLI detection with a mocked model and alert source
- `test_scenario.py` - YAML parsing and validation

### Integration tests (slow, require dependencies)

- `test_engine_real_mvad.py` - Real MVAD library, small windows and fixed seeds (marked `slow`)
- `test_backends.py` (`TestMVADBackend`) - Real MVAD library against verdicts recorded in `tests/assets/sonar_mvad_regression.json` (marked `slow`)
- `test_packaging.py` - Builds the wheel and runs its `sonar` package from a temporary directory (marked `slow`)

## Test fixtures

### Temporary data

Tests that need files use `tempfile.mkdtemp()`:
- `test_local_data_provider.py` - Creates JSON alert files
- `test_scenario.py` - Creates temporary YAML scenarios

### Mock data

Common mock patterns:
```python
# Mock Wazuh alerts
alerts = [
    {"timestamp": "2025-12-30T10:00:00Z", "rule": {"level": 3}},
    {"timestamp": "2025-12-30T10:05:00Z", "rule": {"level": 5}},
]

# Mock MVAD results: one dict per scored bucket (severity = score / (e - 1), 0 if not anomalous)
results = [
    {"index": pd.Timestamp("2025-12-30T10:00:00Z"), "is_anomaly": False, "score": 0.1, "severity": 0.0},
    {"index": pd.Timestamp("2025-12-30T10:05:00Z"), "is_anomaly": True, "score": 0.9, "severity": 0.52},
]

# Mock HTTP response
mock_resp = MagicMock()
mock_resp.json.return_value = {"hits": {"hits": []}}
```

## Adding new tests

### For new modules

1. Create `test_<module_name>.py`
2. Import module and dependencies
3. Use `unittest.TestCase` classes
4. Mock external dependencies
5. Test happy path and error cases

Example:
```python
import unittest
from unittest.mock import patch, MagicMock
from sonar.new_module import NewClass

class TestNewClass(unittest.TestCase):
    def setUp(self):
        self.obj = NewClass()
    
    def test_basic_functionality(self):
        result = self.obj.method()
        self.assertEqual(result, expected_value)
```

### For existing modules

Add test methods to existing test classes:
```python
def test_new_feature(self):
    """Test description."""
    # Arrange
    data = create_test_data()
    
    # Act
    result = self.obj.new_method(data)
    
    # Assert
    self.assertEqual(result, expected)
```

## Mocking patterns

### HTTP requests

```python
@patch("sonar.wazuh_client.requests.Session")
def test_api_call(self, mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session
    
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"data": "value"}
    mock_session.get.return_value = mock_resp
    
    # Test code using client
```

### File operations

```python
def test_with_temp_file(self):
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write(json.dumps(data))
        temp_path = f.name
    
    try:
        # Test code using temp_path
        pass
    finally:
        os.unlink(temp_path)
```

### Time-dependent code

```python
@patch("sonar.module.datetime")
def test_time_sensitive(self, mock_datetime):
    mock_datetime.now.return_value = datetime(2025, 12, 30, 10, 0, 0)
    # Test code
```

## Common issues

### Import errors

If tests fail with import errors, check:
1. Is the module path correct?
2. Are dependencies installed? (`poetry install --with test`)
3. Is `__init__.py` present in package directories?

### Mock not working

If mocks aren't being called:
1. Check the patch path matches the import in the tested module
2. Use `patch("module.Class")` not `patch("Class")`
3. Verify mock is set up before calling tested code

### Slow tests

If tests are slow:
1. Mock external services (HTTP, database, filesystem)
2. Use small test datasets
3. Avoid actual model training in tests
4. Consider using test stubs instead of real dependencies

## Test statistics

Run this to get coverage stats:
```bash
cd /home/alab/soar
poetry run pytest tests/sonartests/ --cov=sonar --cov-report=term-missing
```

Target: **>90% coverage** for all core modules

## Future enhancements

### Needed tests

1. **CLI integration tests** - Full command execution
2. **Data injection tool tests** - `inject_wazuh_data.py`
3. **End-to-end tests** - Complete train → detect workflows
4. **Performance tests** - Large dataset handling
5. **Error recovery tests** - Network failures, corrupted data

### Test improvements

1. Add property-based testing with `hypothesis`
2. Add mutation testing to verify test quality
3. Set up CI/CD pipeline with automatic test runs
4. Add benchmark tests for performance tracking

## Contributing

When adding features:
1. Write tests first (TDD)
2. Aim for >90% coverage of new code
3. Mock external dependencies
4. Keep tests fast (<0.1s per test)
5. Use descriptive test names
6. Document complex test setups

## See also

- [SONAR documentation](../../docs/manual/sonar_docs/README.md)
- [Setup guide](../../docs/manual/sonar_docs/setup-guide.md)
- [Troubleshooting](../../docs/manual/sonar_docs/troubleshooting.md)
