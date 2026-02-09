
# Tutorial for creating an ADBox detector dashboard in Wazuh

Here we provide a complete tutorial ranging from use case definition to building a custom Wazuh dashboard for a nicely formatted and dynamically generated visualization of the ADBox prediction results for an easier and more efficient analysis.

Our *(informal)* objectives are as follows:
1. to create a detector that correlates the number of alerts with memory usage;
2. to get predictions starting from the start of the month until now;
3. to start realtime prediction;
4. to build a dedicated monitoring dashboard.

**Note** that the chosen setting is similar to the one in the [example using notebooks](./example.md).

**Outline**

- [Creating a shipping detector](#step-1-create-a-shipping-detector)
- [Running real time prediction](#step-2-run-real-time-prediction)
- [Creation a detector dashboard](#step-3-create-a-detectors-dashboard)


## Step 1: Create a (shipping) detector

To achieve (1), we make the following selections:
- features  
  - `data.memory_usage_%` (`avg`)
  - `data.cpu_usage_%`  (`avg`)
  - `rule.firedtimes` (`count`)
- training index: October 2024
- name: `detector_test_mem_cpu_alert_count`
- granularity: `30s`
- detection interval: 5.5 min (`window_size` 10)
- training epochs: 30

For (2), we have to choose `HISTORICAL` prediction with `start_time` `2024-11-01T00:00:00Z`. Indeed, if not specified, the end time is determined using the request's timestamp.

### Step 1.1: Define a use case (training + historical prediction)

We define a use case:

```yaml
training:
  aggregation: true
  aggregation_config:
    features:
      data.cpu_usage_%:
      - average
      data.memory_usage_%:
      - average     
      rule.firedtimes:
      - count
    fill_na_method: Zero
    granularity: 30s
    padding_value: 0
  categorical_features: false
  columns:
  - data.memory_usage_%
  - data.cpu_usage_%
  - rule.firedtimes
  display_name: detector_test_mem_cpu_alert_count
  index_date: '2024-10-*'
  train_config:
    epochs: 30
    window_size: 10

prediction: 
    run_mode: HISTORICAL
    start_time: "2024-11-01T00:00:00Z"
```

Let's assume we have cloned the repository into `/home/user/SIEM-MTAD-GAT` and there are already 12 use cases defined, we must save our newly created ones at `/home/user/SIEM-MTAD-GAT/siem_mtad_gat/assets/drivers/uc_13.yaml`.

We have chosen to unify the training and historical prediction into a single use case. However, by creating two separate use cases (one for training and one for historical prediction) and running them in sequence, we would obtain the same result.

### Step 1.2: Create detector and run historical prediction

(Re)build ADBox container:

```sh
$ ./build-adbox.sh
```

Run ADBox with the shipping option/flag:

```sh
$ ./adbox.sh -u 13 -s
```
![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_1-uc-13.png)

#### Effects
The effect of this command is:
- the creation of a [detector folder](/docs/manual/detector_data_structure.md) 
`../siem_mtad_gat/assets/detector_models/baa9b7bf-e05d-4ce9-a1c1-3e82ff4c9f15`

    ```sh
    baa9b7bf-e05d-4ce9-a1c1-3e82ff4c9f15
    ├── input
    │   ├── detector_input_parameters.json
    │   └── training_config.json
    ├── prediction
    │   ├── uc-13_predicted_anomalies_data-1_2024-11-08T09:43:41Z.json
    │   └── uc-13_predicted_data-1_2024-11-08T09:43:41Z.json
    └── training
        ├── losses_train_data.json
        ├── model.pt
        ├── scaler.pkl
        ├── spot
        │   ├── spot_feature-0.pkl
        │   ├── spot_feature-1.pkl
        │   ├── spot_feature-2.pkl
        │   └── spot_feature-global.pkl
        ├── test_output.pkl
        ├── train_losses.png
        ├── train_output.pkl
        └── validation_losses.png
    ```
- the creation of a [detector data stream](/docs/manual/detector_data_stream.md) `adbox_detector_mtad_gat_baa9b7bf-e05d-4ce9-a1c1-3e82ff4c9f15` in the Wazuh indexer and its corresponding template and template component. 
This can be verified by accessing the Wazuh dashboard, and navigating to **Indexer Management>Index Management** (see figures below).
    ![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_2_index_mgm.png)
    ![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_3_data_streams.png)
    ![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_4-templates.png)
    ![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_5_tamplate-components.png)
    ![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_6_temp-comp-open.png)
    ![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_7_temp-open.png)

- the addition of historical prediction. This can be either verified by following the steps explained in [dashboard integration](/docs/manual/detector_data_stream.md#integrate-in-wazuhs-dashboard) or using the Wazuh Indexer API (OpenSearch API) at **Indexer Management>Dev Tools**.
   ![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_34-search-API.png)

## Step 2: Run real time prediction

To achieve (3), we need a different use case choosing `realtime`.

If not specified, the engine runs the prediction pipeline with the last trained detector.

### Step 2.1: Define/find a use case (realtime)

To specify a detector, save a new use case `../siem_mtad_gat/assets/drivers/uc_14.yaml`

```yaml
prediction: 
  run_mode: "realtime"
  detector_id: "baa9b7bf-e05d-4ce9-a1c1-3e82ff4c9f15"
```

Otherwise, we can use an already defined use case `../siem_mtad_gat/assets/drivers/uc_7.yaml`
```yaml
prediction: 
  run_mode: "realtime"
```
### Step 2.2: Realtime prediction

#### Before starting

- **Tip 1**: If you have defined a custom use case, remember to rebuild the container.
- **Tip 2**: If you plan to close the terminal, use GNU `screen` to be able to detach while the detector keeps running

  ![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_26-realtime-1.png)

- **Tip 3**: Start the realtime prediction immediately after training, to avoid losing data points. If not, you can use a tailored historical use case to retrieve the missing windows.

#### Start prediction
Run `./adbox.sh -u 13 -s`

![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_27-realtime-2.png)
![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_28-realtime-3.png)

#### Effects
The effect of this command is:
- updating the detector's folder
    ```sh
    baa9b7bf-e05d-4ce9-a1c1-3e82ff4c9f15
    ├── input
    │   ├── detector_input_parameters.json
    │   └── training_config.json
    ├── prediction
    │   ├── spot
    │   │   ├── spot_feature-0.pkl
    │   │   ├── spot_feature-1.pkl
    │   │   ├── spot_feature-2.pkl
    │   │   └── spot_feature-global.pkl
    │   ├── uc-13_predicted_anomalies_data-1_2024-11-08T09:43:41Z.json
    │   ├── uc-13_predicted_data-1_2024-11-08T09:43:41Z.json
    │   ├── uc-7_predicted_anomalies_data-1_2024-11-08T09:45:38Z.json
    │   └── uc-7_predicted_data-1_2024-11-08T09:45:38Z.jso
    └── training
        ├── losses_train_data.json
        ├── model.pt
        ├── scaler.pkl
        ├── spot
        │   ├── spot_feature-0.pkl
        │   ├── spot_feature-1.pkl
        │   ├── spot_feature-2.pkl
        │   └── spot_feature-global.pkl
        ├── test_output.pkl
        ├── train_losses.png
        ├── train_output.pkl
        └── validation_losses.png
    ```
- shipping new documents to the indexer. This can be easily verified by using the steps explained in [dashboard integration](/docs/manual/detector_data_stream.md#integrate-in-wazuhs-dashboard).

## Step 3: Create a detector dashboard

### Step 3.1 Add pattern

Add the detector data stream pattern to the Wazuh dashboard as explained in [dashboard integration](/docs/manual/detector_data_stream.md#integrate-in-wazuhs-dashboard).

### Step 3.2 Create a Detector dashboard

In the Wazuh dashboard (ref. version 4.8.1)

- Go to **Explore>Dashboard**
    ![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_14-Dashboard.png)
- Click on **Create Dashboard**    
    ![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_15-Dashboard-1.png)
- Save empty Dashboard     
    ![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_18-Dashboard-4.png){: width="50%"}

### Step 3.3 Add visualizations  

A dedicated dashboard can include different visualizations that provide a complete overview.
We provide some examples both regarding global and feature-wise statistics.
Indeed, even though feature-wise scores and thresholds do not contribute to determining if a window is anomalous, 
they can help us understand trends in time series. See also [Example](/docs/manual/example.md).

Since the detector data stream `adbox_detector_mtad_gat_baa9b7bf-e05d-4ce9-a1c1-3e82ff4c9f15` was defined using a dedicated template,
we can manipulate all the numerical fields.

Eventually, the dashboard should look as shown below:
![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_25-Dashboard-10.png)

#### Global score and threshold

The [MTAD-GAT](/docs/manual/mtad_gat.md) algorithm marks as anomalous windows with an anomaly score higher than the local threshold. Therefore, as base graphic we add visualizations showing both these parameters in our timeseries . 

![Video](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_19-Dashboard-video.gif)

**Remarks**:

- We used vizbuilder, but different option are also valuable

    ![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_16-Dashboard-2.png){: width="50%"}

- Remember to select the correct pattern. Moreover, for aggregating
  score and threshold we suggest using `max` to be sure to visualize anomalies.

    ![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_17-Dashboard-3.png){: width="80%"}

#### Feature-wise score and threshold

Using the same visualization type for every feature, we add a visualization 
for feature-wise score and threshold to the dashboard.

![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_20-Dashboard-5.png)

#### Feature-wise true, forecasted and reconstructed univariate timeseries

Among the feature-wise fields of the `adbox_detector_mtad_gat_baa9b7bf-e05d-4ce9-a1c1-3e82ff4c9f15` document, 
we find the (preprocessed) true value, its forecasted and reconstructed univariate timeseries for every feature.
Therefore, we can build a visualization comparing them. 

- **Tip 1:** use the same aggregation method defined at training time for consistency.
  ![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_21-Dashboard-6.png)
- **Tip 2:** Place feature-wise graphics next to each other
  ![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_22-Dashboard-7.png)

#### Anomaly table

We use a table to display numerical and boolean values explicitly.

 ![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_31-Table.png){: width="80%"}

#### Anomaly gauge

Gauges provide a fairly simple visualization. 
Simply adding a filter using the using the boolean field `is_anomaly` with the count metric we get an anomaly counter.

 ![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_35-anomalies-gauge.png){: width="70%"}

### Step 3.3 Complement with visualizations using other indices

To complement the data produced by the detector, we add some visualizations using the index pattern
`wazuh-alerts-*` to the dashboard. Namely, information from the the original data.

- A table displaying the value of original data.
  ![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_24-Dashboard-9.png){: width="80%"}

- A time series line plot displaying the value of original memory and cpu usage in percentage.
  ![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_33-wazuh-realdata.png){: width="80%"}

- A time series line plot displaying the alert counts.
  ![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_32-wazuh-count.png){: width="80%"}

## (Finally) monitor

Combining Discover Dashboard and our Detector Dashboard we can investigate anomalies.
![](/docs/manual/_figures/1BA5_Tutorial_Dashboard/1BA5_36-Dashboard-video-2.gif)