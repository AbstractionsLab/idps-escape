# SONAR evaluation on labelled synthetic data

Evidence for [TRP-060](../../TRP-060.md), [TRP-063](../../TRP-063.md) (the `pca` backend), the calibration of `radar_linux_resource_utilization` (SRS-081) and the extraction gate (`DEC-2026-11-19-sonar-extraction-gate`). Each `<scenario_id>-<backend>.json` is the full `sonar evaluate` record (settings, calibration and every event's outcome). The Markdown summaries `sonar evaluate` also writes are not kept here: Doorstop would load them as TRP items. `labels/` holds the label files of the validation and test splits. Method and metric definitions: [evaluation guide](../../../../manual/sonar_docs/evaluation-guide.md).

## Results

Test split, with the decision rule calibrated on the validation split (budget: 5 false alarms per day). For `mvad` and `ewma`, the `configured` columns use the scenarios' settings before calibration (no threshold, their former `min_consecutive`). The `pca` reports were produced later, with the scenarios' MVAD-calibrated settings, so their `configured` rows say nothing about `pca` and are left out here.

| Scenario | Backend | Configured F1 | Configured false alarms/day | Calibrated `threshold`, `min_consecutive` | Precision | Recall | F1 | Mean delay (min) | False alarms/day | Training (s) |
|---|---|---|---|---|---|---|---|---|---|---|
| `resource_monitoring` | mvad | 0.57 | 9.39 | 0.05, 4 | 0.92 | 1.00 (12/12) | **0.96** | 1.0 | 0.52 | 233 |
| `resource_monitoring` | pca | n/a | n/a | 0.65, 3 | 0.92 | 1.00 (12/12) | **0.96** | 1.0 | 0.50 | 0.1 |
| `resource_monitoring` | ewma | 0.80 | 0.00 | none, 1 | 1.00 | 0.67 (8/12) | 0.80 | 2.0 | 0.00 | < 1 |
| `radar_resource_utilization` | mvad | 0.23 | 41.20 | 0.25, 5 | 1.00 | 1.00 (12/12) | **1.00** | 1.2 | 0.00 | 192 |
| `radar_resource_utilization` | pca | 0.51 | 11.51 | 0.65, 5 | 1.00 | 1.00 (12/12) | **1.00** | 1.2 | 0.00 | < 1 |
| `radar_resource_utilization` | ewma | 0.80 | 0.00 | none, 1 | 1.00 | 0.67 (8/12) | 0.80 | 2.0 | 0.00 | < 1 |
| `brute_force` | mvad | 0.43 | 2.90 | 0.2, 3 | 0.73 | 0.75 (6/8) | 0.74 | 11.0 | 0.32 | 358 |
| `brute_force` | pca | n/a | n/a | none, 4 | 1.00 | 1.00 (8/8) | **1.00** | 4.1 | 0.00 | 0.1 |
| `brute_force` | ewma | 0.05 | 28.12 | 0.95, 5 | 0.21 | 1.00 (8/8) | 0.35 | 2.2 | 3.00 | < 1 |
| `lateral_movement` | mvad | 0.15 | 0.89 | 0.2, 5 | 0.25 | 0.25 (1/4) | 0.25 | 12.0 | 0.33 | 363 |
| `lateral_movement` | pca | n/a | n/a | none, 1 | 1.00 | 0.50 (2/4) | **0.67** | 38.0 | 0.00 | 0.1 |
| `lateral_movement` | ewma | 0.25 | 2.40 | 0.6, 5 | 0.50 | 0.50 (2/4) | 0.50 | 12.0 | 0.20 | < 1 |
| `privilege_escalation` | mvad | 0.25 | 2.66 | 0.35, 1 | 0.67 | 1.00 (4/4) | 0.80 | 13.0 | 0.22 | 207 |
| `privilege_escalation` | pca | n/a | n/a | none, 1 | 1.00 | 1.00 (4/4) | **1.00** | 13.0 | 0.00 | 0.1 |
| `privilege_escalation` | ewma | 0.16 | 4.11 | 0.6, 3 | 0.33 | 0.25 (1/4) | 0.29 | 14.0 | 0.20 | < 1 |

Observations:

- `pca` (window 3, 95 % of the variance) matches MVAD on resource monitoring (0.96) and beats it on the other three scenarios: brute force 1.00 against 0.74, lateral movement 0.67 against 0.25, privilege escalation 1.00 against 0.80, all with at most 0.5 false alarms per day. It trains in about 0.1 s where MVAD takes 3.5 to 6 minutes, and needs no torch.
- These results favour `pca` in one respect: its two settings were chosen on the validation splits (window 1, 3, 5 or 10; variance 0.9 or 0.95), while MVAD ran with the scenarios' own settings. The test splits played no part in the choice. At window 10, `pca` found no privilege escalation at all, so the setting matters.
- `pca` still finds only half of the lateral movements, like `ewma`: the features, not the detector, limit that scenario.
- MVAD beats the `ewma` baseline by at least 0.10 F1 on three of the four scenarios (resource +0.16, brute force +0.39, privilege escalation +0.51) and loses on lateral movement (−0.25), where neither detector finds most of the movements.
- `ewma` misses every memory leak: a gradual drift stays within its per-feature z-score until late. MVAD and `pca` flag all four.
- At the scenarios' former settings, MVAD raises too many alarms (resource monitoring: 9.4 false alarms per day); the calibrated decision rule is what makes it usable. The calibrated values are now in `sonar/scenarios/*.yaml`.
- `radar_resource_utilization` is the resource splits rewritten as RADAR events (`sonar/test_data/radar_format.py`): the same samples and labels, with only RADAR's two metrics (mean and maximum per minute) instead of the resource scenario's seven numeric fields, five derived counts and categorical columns. MVAD and `pca` find every event without a false alarm on the test split, at least as well as on the full resource feature set. Its `configured` rows are the scenario before calibration (no threshold, `min_consecutive` 1) for all three backends.
- The splits hold 4 to 12 events per scenario: one detection more or less moves recall by 0.08 to 0.25. Treat differences below about 0.25 F1 as indicative only.

## Reproducing

Environment: dev container, 12 CPUs, Python 3.10.12, torch 2.3.0, `time-series-anomaly-detector` 0.4.0. Run the MVAD evaluations one at a time: two concurrent MVAD trainings oversubscribe the CPU threads and run about 30 times slower.

```bash
poetry run python sonar/test_data/generate_resource_data.py --evaluation --output-dir eval/resource   # seed 42
poetry run python sonar/test_data/generate_attack_data.py --evaluation --output-dir eval/auth         # seed 42
for f in training validation test; do poetry run python sonar/test_data/radar_format.py eval/resource/$f.json eval/radar/$f.json; done
cp eval/resource/*_labels.json eval/radar/
cd eval
run() {  # scenario, data directory, event types, tolerance (one bucket), backend
  poetry -C /path/to/idps-escape run sonar evaluate --scenario "$1" --backend "$5" \
    --train-file "$2/training.json" --validation-file "$2/validation.json" --validation-labels "$2/validation_labels.json" \
    --test-file "$2/test.json" --test-labels "$2/test_labels.json" --event-types "$3" --tolerance-minutes "$4" --output-dir reports
}
for b in ewma mvad pca; do
  run radar_linux_resource_utilization radar cpu_spike,memory_leak,fork_bomb 1 $b
  run linux_resource_monitoring resource cpu_spike,memory_leak,fork_bomb 1 $b
  run brute_force_detection auth brute_force,password_spray 5 $b
  run lateral_movement_detection auth lateral_movement 10 $b
  run privilege_escalation_detection auth privilege_escalation 15 $b
done
```

The `mvad` and `ewma` reports were produced with the scenarios' pre-calibration detection settings (`threshold: null`, `min_consecutive` 3, 2, 3 and 1), which are the `test (configured)` rows; the `pca` reports with the calibrated scenarios. Rerunning changes only the `test (configured)` rows. MVAD training is seeded by the library's default seed, so reruns on the same platform reproduce the results; another torch build may differ slightly.

## Not covered here

- **OpenSearch anomaly detection plugin baseline**: needs the lab indexer. For resource utilization, RADAR's deployed detector is that baseline: [RADAR comparison guide](../../../../manual/sonar_docs/radar-comparison-guide.md). Procedure: [Comparing with another detector](../../../../manual/sonar_docs/evaluation-guide.md#the-opensearch-anomaly-detection-plugin-baseline).
- **Lab capture**: no labelled capture of the 4.14.1 stack with scripted red-team activity exists yet. Procedure: [Recording a lab capture](../../../../manual/sonar_docs/evaluation-guide.md#recording-a-lab-capture).
