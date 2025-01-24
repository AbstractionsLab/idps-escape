# Use-case guide 

The anomaly detection pipeline via ADBox can be easily customize by creating a **use-case**. In this context, a use-case 
is a sequence of actions to be performed and the characteristics of the desired outcome. 

Examples of "informal" use-cases are:
1. Create and train a detector using data about the Linux resource usage using data from March.
2. Create and train a detector using data about the Linux resource usage using data from March and apply it to check if there were anomalies on May the 3rd.
3. Use detector X for real-time detection.
4. Use detector X for batch detection on batches of 10 windows at the time.
 
These informal use-cases can be translated into real action by using a provided [YAML template](/siem_mtad_gat/assets/drivers/driver.yaml), as explained in the following section. 
 
## Writing a use-case as YAML File

The YAML file for detector training and prediction includes parameters to configure the training and prediction processes. Below is a guide explaining the purpose of each parameter, its default value, and format.

**Attention:** Default values are specified in [default configuration file](/siem_mtad_gat/assets/default_configs/default_detector_input_config.json). If the file is changed they may not coincide with those listed below.

### Training Input Parameters
#### 1. index_date
Represents the data source index where the training data should be fetched from.
-   **Default value**:  `default` which will be processed as `{current_year}-{current_month}-*` (fetches all data for the current month).
-   **Format**: `YYYY-MM-DD` or with wildcards (`*`).

#### 2. categorical_features
Specifies if the given input features include categorical features.
-   **Default value**: `False`.
-   **Format**: Boolean (`True` or `False`).

#### 3. columns
List of columns used as features to train the detector.
-   **Default value**: `rule.firedtimes`, `rule.level`.
-   **Format**: List of strings.

#### 4. aggregation
 Specifies if the column values should be aggregated.
-   **Default value**: `True`.
-   **Format**: Boolean (`True` or `False`).

#### 5. aggregation_config
-  Configuration for data aggregation. Required if `aggregation` is `True`.
    -   **fill_na_method**: Method to handle null values.
        -   **Default value**: `Zero`.
        -   **Format**: String to be selected from `"Linear"`, `"Previous"`, `"Subsequent"`, `"Zero"` or `"Fixed"`.
    -   **padding_value**: Value used when `fill_na_method` is `Fixed`.
        -   **Default value**: `0`. 
        -   **Format**: Integer (if `fill_na_method` is `Fixed`).
    -   **granularity**: Granularity to aggregate the input data.
        -   **Default value**: `1min`.
        -   **Format**: String (`"1min"`, `"5min"`, `"1s"`, `"1hour"`, etc.).
    -   **features**: Key-value pairs of features and aggregation methods.
        -   **Default value**:
            -   `rule.firedtimes`: `["average", "max"]`.
            -   `rule.level`: `["average", "max"]`.
        -   **Format**: String to list of strings. Aggregation method to be selected among `"average"`, `"max"`, `"min"`, `"count"`, or `"sum"`. 

#### 6. train_config

-   **Description**: Configurations for model training.
    -   **window_size**: Size of the training window.
        -   **Default value**: `10`.
        -   **Format**: Integer.
    -   **epochs**: Number of epochs for training.
        -   **Default value**: `8`.
        -   **Format**: Integer.

#### 7. display_name

-   **Description**: Name for the detector.
-   **Default value**: `default` which is converted as`detector_<current timestamp>`. 
-   **Format**: String.

### Prediction/Detection Input Parameters

#### 1. run_mode

-   **Description**: Specifies the detection run mode.
-   **Default value**: `default`. (`"historical"` run mode). 
-   **Format**: String (`"historical"`, `"batch"`, `"realtime"`).
	- **HISTORICAL**: Performs detection on historical data.
    - **BATCH**: Performs detection on current data in batches.
    - **REALTIME**: Performs detection on real-time data.

#### 3. detector_id

-   **Description**: Detector ID for the selected detector.
-   **Default value**: `default` (most recently trained detector).
-   **Format**: String.

#### 4. start_time

-   **Description**: Start time for detection.
-   **Default value**: `default` (start of the current day at midnight).
-   **Format**: `YYYY-MM-DDTHH:MM:SSZ`. 

#### 5. end_time

-   **Description**: End time for detection.
-   **Default value**: `default` (current timestamp).
-   **Format**: `YYYY-MM-DDTHH:MM:SSZ`.  

#### 6. batch_size

-   **Description**: Batch size for the `batch` run mode.
-   **Default value**: `10`.
-   **Format**: Integer.

### Example use-case yaml file: 


```yaml 
training: 
  index_date: "default"
  categorical_features: false
  columns: 
    - "rule.firedtimes"  
    - "rule.level"  
  aggregation: true
  aggregation_config: 
    fill_na_method: "Zero"
    granularity: "1min"
    features: 
      rule.firedtimes:
        - "average"
        - "max"
      rule.level:
        - "average"
        - "max"
  train_config: 
    window_size: 10
    epochs: 8
  display_name: "default"

prediction: 
  run_mode: HISTORICAL
  detector_id: "default"
  start_time: "default"
  end_time: "default"
 ```

## Default behavior and use-case parsing

 The engine parses and transforms use-case input to data consumable by the detection pipelines, by calling the [`DetectorsConfigManager`](/siem_mtad_gat/config_manager/config_manager.py). The manager reads the default values from the [default configuration file](/siem_mtad_gat/assets/default_configs/default_detector_input_config.json). 

 Notice that there are special key whose default value depends on the function call time (i.e., **dynamic default values**). See key name mapping [`config_keys`](/siem_mtad_gat/config_manager/config_keys.py).
 
 For them, if their value is `default`, a special methods are called to determine the present value.

 
 ### For training: `get_train_config_from_uc_yaml`
    
  If the key `config_keys.UC_TRAINING` (i.e, `training`) is missing in the input use-case yaml file, `get_train_config_from_uc_yaml` returns `None`.

   Otherwise, when either no use-case number or key values are provided it completes the training configuration dictionary, using get the default configuration values.
 
  - **Dynamic default values** for training: 

    - *detector name*: based on request's timestamp
        
    - *input index*: current month
        
  ### For prediction: `get_predict_config_from_uc_yaml`
   
   If either the key `config_keys.UC_PREDICTION` (i.e, `prediction`) is missing in the input uc or no use-case number is specified,`get_predict_config_from_uc_yaml` returns `None`. Otherwise, it uses the default configuration file to get the default values, whenever key values are missing. The keys' list depends on the *runmode*. 
   
   - *Real time*: only `detector_id`
   - *Batch*: `detector_id`, `batch_size`
   - *Historical*: `detector_id`, `start_time`, `end_time`.

   - **Dynamic default values** for prediction:
      - *detector id*: last trained detector
      - *start time*: current day at midnight
      - *end time*: current timestamp