# Models: names, locations and file format

This guide explains where SONAR keeps its models and other files, how a model gets its name, what a model directory contains, and how to protect it. To choose the detector a model uses (`mvad`, `pca` or `ewma`), see [backend](./scenario-guide.md#backend) in the scenario guide.

## Where SONAR keeps its files

No path depends on the directory you run SONAR from:

- A relative path **in a configuration or scenario file** is relative to that file. This applies to `models_dir`, `debug.data_dir`, `output.state_dir`, `output.jsonl_path`, `output.wazuh.file_path` and, in a scenario, `detection.payload_dir`.
- A path **on the command line** (`--config`, `--scenario`, `--use-case`, `--payload-dir`) is relative to the shell's current directory, as usual.
- A path you leave unset defaults to a location in the **SONAR home**.

The SONAR home is, in this order:

1. `$SONAR_HOME`, if the variable is set;
2. the `sonar/` package directory, when SONAR runs from a source checkout (`pyproject.toml` next to the package): this repository, and the Docker image built from it;
3. `~/.sonar`, when SONAR is installed from a wheel.

| Setting | Default |
|---------|---------|
| `models_dir` | `<home>/models` (`sonar/models/` in this repository) |
| A model | `<models_dir>/<model_name>/` |
| `output.state_dir` (delivery watermarks) | `<models_dir>/state` |
| `output.jsonl_path` (`jsonl` sink) | `<home>/anomalies.jsonl` |
| Dry-run directory (`--payload-dir`, `detection.payload_dir`) | `<home>/payloads` |
| `debug.data_dir` | the packaged `sonar/test_data/synthetic_alerts` |

For example, a service that keeps everything under `/var/lib/sonar`:

```bash
export SONAR_HOME=/var/lib/sonar
poetry run sonar scenario --use-case sonar/scenarios/brute_force_detection.yaml
# model: /var/lib/sonar/models/brute_force_detection/
# watermarks: /var/lib/sonar/models/state/brute_force.json
```

Or, without the variable, in the configuration file:

```yaml
# /etc/sonar/sonar.yaml
models_dir: /var/lib/sonar/models   # a relative value would be relative to /etc/sonar/
```

In this repository, `.gitignore` ignores everything in `sonar/models/` except `.gitkeep`, so trained models and watermarks are never committed.

## Model names

Every command reads and writes the model `<models_dir>/<model_name>/`. The name comes from:

| Run | Model name |
|-----|------------|
| `sonar scenario --use-case`, `sonar train --scenario`, `sonar detect --scenario` | The scenario's `model_name`, else its `name` in lower case with every run of characters outside `[a-z0-9_-]` replaced by `_` (`"Brute Force Detection"` → `brute_force_detection`) |
| `sonar train`, `sonar detect` with `--config` or the default configuration | The configuration's top-level `model_name` (default `sonar`) |
| `sonar train --model-name NAME` (with or without `--scenario`) | `NAME` |
| Any of these with `--agent HOST` | The name above, then `-` and `HOST` in the same character rules (`radar_linux_resource_utilization-web-01`). `train`, `detect`, `scenario`, `evaluate` and `export` all add it, so they find the same per-host model |

`sonar detect` and `sonar scenario` have no `--model-name`; they use the scenario's or the configuration's name. A scenario always sets the name, so a `model_name` in the `--config` file applies only to runs without a scenario.

The name does not change from one run to the next, so separate commands find the same model:

```bash
# brute_force_detection.yaml has no model_name: both use sonar/models/brute_force_detection/
poetry run sonar train --scenario sonar/scenarios/brute_force_detection.yaml
poetry run sonar detect --scenario sonar/scenarios/brute_force_detection.yaml
```

Training again under the same name replaces the model. To keep the previous one, train under a new name:

```bash
poetry run sonar train --scenario sonar/scenarios/brute_force_detection.yaml --model-name brute_force_v2
```

A configuration file may still contain the old `model_path` key. SONAR reads it with a deprecation warning and splits it into `models_dir` (its directory) and `model_name` (its last component, without `.pkl`). Replace it with `models_dir` and `model_name`.

### The scenario ID

The scenario ID names the anomaly data stream (`sonar_anomalies_mvad_<scenario_id>`), the watermark file (`<state_dir>/<scenario_id>.json`), the `sonar.scenario` field of the Wazuh events, and the namespace of every `anomaly_id`. It is `shipping.scenario_id` when set, otherwise the model name in lower case (same character rules as above). With `--agent HOST`, an explicit `shipping.scenario_id` also gets `-HOST`, so every host has its own stream, watermarks and anomaly IDs.

Without `shipping.scenario_id`, a new model name therefore starts a new data stream and new watermarks, and anomalies already delivered under the old ID can be delivered again, also to the Wazuh manager, which cannot recognise duplicates. The bundled detection scenarios (not the `example_*.yaml` templates) set `shipping.scenario_id`; set it in your own scenarios before you version their models. See [Delivery and the watermark](./scenario-guide.md#delivery-and-the-watermark).

## Model file format

A model is a directory:

```
sonar/models/linux_resource_monitoring/
├── metadata.json       # what the model is and how it was trained
├── mvad_config.json    # mvad backend: the library's configuration and training statistics
└── mvad_weights.pt     # mvad backend: the network's weights, a plain tensor dictionary
```

A `pca` model holds `pca_state.json` (its settings, the median and scale of each column, the principal components, their variances, the noise variance and the training score distribution) and an `ewma` model `ewma_state.json` (smoothing factor, threshold, and the median and scale of each column) instead of the two `mvad_*` files.

`metadata.json` records:

| Key | Content |
|-----|---------|
| `format_version` | Model format version, currently 1 |
| `sonar_version` | SONAR version that trained the model |
| `backend` | `mvad`, `pca` or `ewma` |
| `feature_schema_version` | Feature schema the columns were built with (currently 2) |
| `feature_config`, `vocabulary`, `columns` | The feature contract: feature settings, categorical vocabulary and column order that detection reproduces |
| `training_samples` | Number of training buckets |
| Backend record | `mvad`: `mvad_library`, `mvad_library_version`, `mvad_params`, `training_plan`, `gradient_steps`, `library_threshold`, `train_score_min`, `train_score_max`. `pca`: `pca` (`window`, `variance`, `z_threshold`), `components`, `dimensions`, `noise_variance`, `training_points`. `ewma`: `ewma` (`alpha`, `z_threshold`), `training_points` |

Training writes the new model into a hidden staging directory next to the target and swaps it in only when it is complete, so an interrupted training run leaves the previous model intact.

Loading a model unpickles nothing: the JSON files are parsed, and MVAD's weights are read with `torch.load(weights_only=True)`, which accepts only tensors and plain containers.

SONAR refuses a model it cannot apply correctly, and asks you to retrain it:

- a model in the old single-file pickle format (`<name>.pkl`), which SONAR does not convert (models trained before feature schema 2 need retraining in any case);
- a model with another `feature_schema_version` or `format_version`.

### Protect the models directory

Loading a model no longer runs code from it, but a model still decides what SONAR reports: someone who can replace a model can make SONAR miss attacks or raise false alerts. Treat `models_dir` like the configuration:

- make it writable only by the user that runs SONAR (`chmod 700`, or a dedicated service account);
- in Docker, mount the host's models directory only into the SONAR container;
- copy models between hosts only over a trusted channel, and only from a SONAR version with the same feature schema.

## Examples

### Production model with a stable name

```yaml
# sonar/scenarios/prod_brute_force.yaml
name: "Production Brute Force Detection"
model_name: "prod_brute_force"

shipping:
  scenario_id: "prod_brute_force"   # stable stream and watermarks, whatever the model name

training:
  lookback_hours: 168
  numeric_fields: ["rule.level"]
  extra_params:
    interval: 1

detection:
  mode: "realtime"
  lookback_minutes: 60  # window to score; earlier context is fetched automatically
```

```bash
# Train (creates or replaces sonar/models/prod_brute_force/)
poetry run sonar train --scenario sonar/scenarios/prod_brute_force.yaml

# One-shot detection with that model
poetry run sonar detect --scenario sonar/scenarios/prod_brute_force.yaml
```

`sonar detect` always runs once, whatever `mode` says. For realtime polling, run `poetry run sonar scenario --use-case sonar/scenarios/prod_brute_force.yaml`, which retrains first because the file has a `training:` section.

### Comparing two models

Train two versions:

```bash
poetry run sonar train --scenario sonar/scenarios/prod_brute_force.yaml --model-name dev_v1
# ... change the scenario's training settings ...
poetry run sonar train --scenario sonar/scenarios/prod_brute_force.yaml --model-name dev_v2
```

`sonar detect` has no `--model-name`, so write one configuration file per model: your usual configuration (with its `wazuh:` connection section) plus the model name and, to compare the results side by side, a local sink:

```yaml
# dev_v1.yaml (dev_v2.yaml: the same with dev_v2)
model_name: dev_v1
output:
  sinks: [jsonl]
  jsonl_path: dev_v1.jsonl   # relative to this file
```

```bash
poetry run sonar detect --config dev_v1.yaml --lookback-minutes 1440
poetry run sonar detect --config dev_v2.yaml --lookback-minutes 1440
```

Detection builds its features from each model's stored feature contract, so the configuration files need no feature settings. Without `shipping.scenario_id`, each model has its own scenario ID (`dev_v1`, `dev_v2`) and its own watermarks.

### Running a packaged example outside the repository

An installed SONAR ships its example scenarios; `--use-case` and `--scenario` accept their names when no file of that name exists:

```bash
export SONAR_HOME="$HOME/sonar-lab"
sonar scenario --use-case linux_resource_monitoring --debug
# model: ~/sonar-lab/models/linux_resource_monitoring/
```

## Troubleshooting

### Model not found

```
ERROR: Model not found at /home/alab/soar/sonar/models/my_scenario. Train first, or add a training section to the scenario.
```

The path in the message is the one SONAR looked for. Check that training used the same model name and the same `models_dir` (or `SONAR_HOME`):

```bash
ls sonar/models/
grep -E '^(name|model_name|models_dir):' sonar/scenarios/my_scenario.yaml
```

A run with `--model-name` trains under that name, which a later `sonar detect --scenario` does not know; put the name in the scenario's `model_name`, or detect with a configuration file that sets it.

### Model in the old pickle format

```
ERROR: /home/alab/soar/sonar/models/brute_force_v1.pkl is a model in the old pickle format, which SONAR <version> no longer loads (unpickling can run code). Retrain the model; it will be saved as /home/alab/soar/sonar/models/brute_force_v1/.
```

Retrain under the same name, then delete the `.pkl` file.

### Model replaced by a retraining

Every training run under a name replaces that model. Train under a new name (`--model-name`, or a new `model_name` in a copy of the scenario) to keep the previous one, and set `shipping.scenario_id` so that the new name does not start new watermarks.
