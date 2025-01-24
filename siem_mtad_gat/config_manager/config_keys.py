from siem_mtad_gat.mtad_gat_pytorch.mtad_gat_keys import *

# UC KEYS


UC_DEFAULT="default"
UC_TRAINING="training"
UC_INDEX_DATE="index_date"
UC_CATEGORICAL_FEATURES="categorical_features"
UC_COLUMNS="columns"
UC_AGGREGATION="aggregation"
UC_AGGREGATION_CONFIG="aggregation_config"
UC_FILL_NA="fill_na_method"
UC_PADDING="padding_value"
UC_GRANULARITY="granularity"
UC_FEATURES="features"
UC_TRAIN_CONFIG="train_config"
UC_WINDOW_SIZE="window_size"
UC_EPOCHS="epochs"
UC_DISPLAY_NAME="display_name"
UC_PREDICTION="prediction"
UC_RUN_MODE="run_mode"
UC_START_TIME="start_time"
UC_END_TIME="end_time"  
UC_BATCH_SIZE="batch_size"
UC_DETECTOR_ID="detector_id"
UC_ROUNDING="rounding"
UC_ALL:list[str] = [
    UC_TRAINING,
    UC_INDEX_DATE,
    UC_CATEGORICAL_FEATURES,
    UC_COLUMNS,
    UC_AGGREGATION,
    UC_AGGREGATION_CONFIG,
    UC_FILL_NA,
    UC_PADDING,
    UC_GRANULARITY,
    UC_FEATURES,
    UC_TRAIN_CONFIG,
    UC_WINDOW_SIZE,
    UC_EPOCHS,
    UC_DISPLAY_NAME,
    UC_PREDICTION,
    UC_RUN_MODE,
    UC_START_TIME,
    UC_END_TIME,
    UC_BATCH_SIZE,
    UC_DETECTOR_ID
]
UC_TRAINING_LIST:list[str] = [
    UC_INDEX_DATE,
    UC_CATEGORICAL_FEATURES,
    UC_COLUMNS,
    UC_AGGREGATION,
    UC_AGGREGATION_CONFIG,
    UC_TRAIN_CONFIG,
    UC_DISPLAY_NAME]

UC_HISTORICAL_LIST:list[str] = [
    UC_RUN_MODE,
    UC_START_TIME,
    UC_END_TIME,
    UC_BATCH_SIZE,
    UC_DETECTOR_ID,
    #UC_ROUNDING
]

UC_BATCH_LIST:list[str] = [
    UC_RUN_MODE,
    UC_BATCH_SIZE,
    UC_DETECTOR_ID,
    #UC_ROUNDING
]

UC_REALTIME_LIST:list[str] = [
    UC_RUN_MODE,
    UC_DETECTOR_ID,
    #UC_ROUNDING
]

# Train config keys

CONFIG_TYPE='type'
CONFIG_DEFAULT='default'

