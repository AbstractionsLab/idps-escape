import adbox.config_manager.config_keys as confkeys

## Response keys
RESP_RESULTS="results"
RESP_RUN_MODE=confkeys.UC_RUN_MODE
RESP_DETECTOR_ID=confkeys.UC_DETECTOR_ID
RESP_START_TIME=confkeys.UC_START_TIME
RESP_END_TIME=confkeys.UC_END_TIME

#predicition keys
TIMESTAMP="timestamp"
IS_ANOMALY="is_anomaly"
SCORE="anomaly_score"
PREDICTION_VALUES="features_values"
THRESHOLD="threshold"


#detectors keys
DETECTOR_ID=RESP_DETECTOR_ID
CREATION_TIME="creation_time"
LAST_UPDATE_TIME="last_updated_time"
MODEL_INFO="model_info"
DATASOURCE_TRAIN="datasource_train"

ERRORS="errors"
DYSPLAY_NAME="display_name"
DIAGNOSTIC_INFO="diagnostics_info"
MODEL_STATE="model_state"

TRAIN_CONFIG=confkeys.UC_TRAIN_CONFIG

STATUS="status"
CREATED="CREATED"

DESCRIPTION="description"