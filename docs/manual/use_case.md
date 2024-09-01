# Use case guide 

The anomaly detection pipeline via ADBox can be easily customize by creating a *use case*. In this context, a use case 
is a sequence of actions to be performed and the characteristics of the desired outcome. 
Examples of "informal" use cases are:
1. Create and train a detector using data about the Linux resource usage with using data from March.
2. Create and train a detector using data about the Linux resource usage with using data from March and apply it predict the anomalies on May the 3rd.
3. Use detector X for real-time detection.
4. Use detector X for batch detection on batches of size 10.
 
These informal use cases can be translated into real action by using a provided [YAML template](./../../siem_mtad_gat/assets/drivers/driver.yaml), as explained in the following section. 
 
## Writing a Use Case as YAML File

The YAML file for detector training and prediction includes parameters to configure the training and prediction processes. Below is a guide explaining the purpose of each parameter, its default value, and format.

### Training Input Parameters
#### 1. index_date
Represents the data source index where the training data should be fetched from.
-   **Default value**:  `default` which will be processed as `{current_year}-*-*` (fetches all data for the current year).
-   **Format**: `YYYY-MM-DD` or with wildcards (`*`).

#### 2. categorical_features
Specifies if the given input features include categorical features.
-   **Default value**: `False` (default as features are numerical).
-   **Format**: Boolean (`True` or `False`).

#### 3. columns
List of columns used as features to train the detector.
-   **Default value**: `data.cpu_usage_%`, `data.memory_usage_%`.
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
            -   `data.cpu_usage_%`: `["average", "max"]`.
            -   `data.memory_usage_%`: `["average", "max"]`.
        -   **Format**: String to list of strings. Aggregation method to be selected among `"average"`, `"max"`, `"min"`, `"count"`, or `"sum"`. 

#### 6. train_config

-   **Description**: Configurations for model training.
    -   **window_size**: Size of the training window.
        -   **Default value**: `10`.
        -   **Format**: Integer.
    -   **epochs**: Number of epochs for training.
        -   **Default value**: `30`.
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
#### 2. index_date

-   **Description**: Date string to fetch data from the Wazuh index.
-   **Default value**: `default` (current day).
-   **Format**: `YYYY-MM-DD` or with wildcards (`*`).

#### 3. detector_id

-   **Description**: Detector ID for the selected detector.
-   **Default value**: `default` (most recently trained detector).
-   **Format**: String.

#### 4. start_time

-   **Description**: Start time for detection.
-   **Default value**: `default` (start of the current date).
-   **Format**: `YYYY-MM-DDTHH:MM:SSZ`. 

#### 5. end_time

-   **Description**: End time for detection.
-   **Default value**: `default` (current timestamp of the current date).
-   **Format**: `YYYY-MM-DDTHH:MM:SSZ`.  

#### 6. batch_size

-   **Description**: Batch size for the `batch` run mode.
-   **Default value**: `10`.
-   **Format**: Integer.

### Example use case yaml file: 

```yaml 
training: 
  index_date: "default"
  categorical_features: false
  columns: 
    - "data.cpu_usage_%"  
    - "data.memory_usage_%"  
  aggregation: true
  aggregation_config: 
    fill_na_method: "Zero"
    granularity: "1min"
    features: 
      data.cpu_usage_%:
        - "average"
        - "max"
      data.memory_usage_%:
        - "average"
        - "max"
  train_config: 
    window_size: 10
    epochs: 30
  display_name: "default"

prediction: 
  run_mode: "default"
  index_date: "default"
  detector_id: "default"
  start_time: "default"
  end_time: "default"
  batch_size: 10
 ```