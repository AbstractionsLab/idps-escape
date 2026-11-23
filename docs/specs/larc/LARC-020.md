---
active: true
derived: false
level: 1.2
links:
- SRS-074: dzj0g7pw6HswRcv7ya9MQzj2kRCYUDKOlGE1Un8oaj8=
- SRS-075: bEnvJLOOaAhSlY7zBGwJ0Z_ngTEb8N316Pz7l50Tz18=
- SRS-076: hNuECJG3nfrbswBbDudMSwhvfmER7GkEP9H969GbNxQ=
- SRS-077: uIEdrLiZWIIhcBbB3wVKRrCWxHFVLEXXiW1w2VYJv8Y=
- SRS-078: 6u3XkS_KMEta4pjdLr88rwAz71ObDpCQn3vU_a2RXMk=
- SRS-086: Dpg2bXS2OYN2DLt7-GJr2hgdhvAX723BkkWSzKcdio0=
normative: true
ref: ''
release: Alpha
reviewed: mQ3cmr-_0eVDhUWfi0MBs5VrAW4rlm3HWW8tu2fcZ0A=
version: '0.1'
---

# SONAR detection pipeline sequence

## Detection workflow sequence diagram

The detection pipeline loads a trained model, scores the complete buckets of the detection window, and delivers the new anomalies to the configured sinks. Every detection command (`sonar detect` with or without a scenario, and the detection phase of `sonar scenario`) runs this one sequence (`_run_single_detection` in `sonar/cli.py`); realtime mode repeats it once per bucket.

```plantuml
@startuml
participant "CLI (cli.py)" as CLI
participant "File System" as Storage
participant "ModelEngine\n(engine.py)" as Engine
participant "Data Provider\n(WazuhIndexerClient or\nLocalDataProvider)" as DataProvider
participant "Feature Builder\n(features.py)" as Features
participant "Post-Processor\n(pipeline.py)" as Pipeline
participant "Delivery\n(sinks/, watermark.py)" as Delivery
participant "Sinks" as Sinks

CLI -> Engine: load()
Engine -> Storage: Read model directory
Storage --> Engine: Metadata, backend state
Engine --> CLI: Ready (or error: missing or incompatible model)
CLI -> CLI: Build sinks, fallback and watermark (once per phase)

CLI -> CLI: Adopt the model's feature settings\n(warn if the scenario's differ)
CLI -> CLI: Scored window = complete buckets of the last lookback_minutes;\nadd the context buckets the model needs before it
CLI -> DataProvider: Fetch alerts (context + scored window)
DataProvider --> CLI: Raw alert list

CLI -> Features: Build features (model's vocabulary)
Features --> CLI: Feature matrix

CLI -> Engine: predict(matrix)
Engine -> Engine: Check columns against the model
Engine --> CLI: PointResult per bucket after the context
CLI -> CLI: Keep the buckets of the scored window

CLI -> Pipeline: Build anomaly documents
Pipeline -> Pipeline: Apply minimum severity and minimum run length
Pipeline -> Pipeline: Add anomaly_id, model and scenario metadata
Pipeline --> CLI: Anomaly documents

loop each sink
  CLI -> Delivery: Documents after the sink's watermark
  Delivery -> Sinks: emit(batch)
  Sinks --> Delivery: Accepted prefix
  Delivery -> Delivery: Advance the sink's watermark
end
opt documents rejected and a fallback is configured
  Delivery -> Sinks: Fallback emit(rejected)
end
Delivery --> CLI: Delivery report
CLI -> CLI: Exit status
@enduml
```

## Detection modes

`detection.mode` is read only by `sonar scenario`; `sonar detect` always runs once.

| Mode | Behavior |
|------|----------|
| **historical**, **batch** | One detection run over the window, then exit |
| **realtime** | Repeat the run once per bucket, after the bucket has ended plus `ingest_delay_seconds` (or every `polling_interval_seconds` if set), until stopped |

In realtime mode a failed run is retried after 10 s, doubling per consecutive failure and capped at one bucket; after `max_consecutive_failures` consecutive failures SONAR exits with status 1. A run with too little data is not a failure. SONAR itself does not schedule periodic one-shot runs; a scheduler (cron, a container restart policy) may.

## Scored window

Detection scores the complete time buckets of the last `lookback_minutes`; the current bucket, still filling, is never scored, nor is one that ended less than `ingest_delay_seconds` ago. The model needs a fixed number of earlier buckets as context before the first bucket it can score (derived from its backend's window), so the pipeline fetches them as well and reports only buckets inside the scored window. In debug mode the local file is scored as a whole, without a time range.

## Post-processing steps

1. **Thresholding**: Keep buckets that the backend flags and whose severity (0–1) reaches the configured minimum (`threshold`), if one is set
2. **Consecutive filtering**: Keep only runs of at least `min_consecutive` such buckets, evaluated over the whole scored window before the watermarks are applied
3. **Enrichment**: Add `anomaly_id` (from the scenario ID and bucket start), scenario and model names, severity, raw score, top contributors with their values, and `anomaly_confidence`
4. **Delivery**: Each sink receives the documents after its own watermark; the `wazuh`, `jsonl` and `stdout` sinks send the SONAR event derived from the document, the indexer sinks store the document ([SWD-024](../swd/SWD-024.md)). Debug runs (`output.debug_sinks`) and dry runs (a JSON-lines file) use no watermark

## Exit status

A one-shot run exits with 0 when the window was scored and its new anomalies delivered, 2 when there was too little data to score it (no alerts, or fewer buckets than the model needs), and 1 on an error, including a delivery in which every sink with anomalies to deliver failed and no fallback took them all. When some sinks fail and others succeed, the run logs a warning and exits with 0; the failed sinks catch up on a later run.

## Related documentation

- Detection sequence diagram: `docs/manual/sonar_docs/uml-diagrams.md#detection-workflow`