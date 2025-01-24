# Detector folder

A **detector** is the object that is used to perform detection. In the specific case of anomaly detection via the [MTAD-GAT](/docs/manual/mtad_gat.md) algorithm, it must include for example a trained ML model, along with all the configuration used, and POT object. 
In the ADBox implementation, detectors are formed as a collection of files stored under a unique ID, which is also the name of the subfolder of [`siem_mtad_gat/assets/detector_models`](/siem_mtad_gat/assets/detector_models/) containing such files.

```sh
├── a77c773c-9e6f-4700-92f2-53c0e682f290
│   ├── input
│   │   ├── detector_input_parameters.json
│   │   └── training_config.json
│   ├── prediction
│   │   ├── uc-16_predicted_anomalies_data-1_2024-08-12_13-48-42.json
│   │   └── uc-16_predicted_data-1_2024-08-12_13-48-42.json
│   └── training
│       ├── losses_train_data.json
│       ├── model.pt
│       ├── scaler.pkl
│       ├── spot
│       │   ├── spot_feature-0.pkl
│       │   ├── spot_feature-1.pkl
│       │   ├── spot_feature-2.pkl
│       │   ├── spot_feature-3.pkl
│       │   ├── spot_feature-4.pkl
│       │   └── spot_feature-global.pkl
│       ├── test_output.pkl
│       ├── train_losses.png
│       ├── train_output.pkl
│       └── validation_losses.png
```

## Input

The input folder contains the following files:

- **detector_input_parameters.json**: 
This file is generated as a result of the training input parameters provided in the YAML file.  While reading the file, it can be seen that it contains the same fields as defined above for the YAML file and some other fields that were added after the training of the detector. 

- **training_config.json**: 
This file contains more details about the training parameters at the machine learning level. 
This file is critical for configuring how the MTAD-GAT machine learning model is trained. This specific configuration file includes parameters that define the model architecture, training process, and other hyper parameters. 

## Training

The training folder contains:
- **train_output.pkl**: the saved forecasts, reconstructions, actual, thresholds, etc. on the training dataset in pickle format. 
- **test_output.pkl**:  the saved forecasts, reconstructions, actual, thresholds, etc. on the testing dataset in pickle format. 
- **model.pt**:
This file contains the model parameters of trained model in a .pt file which is a PyTorch file used to save and load model parameters, entire models, or tensor data. 
- **losses_train_data.json**: this file contains the training losses for each epoch. 
- **train_losses.png**: plot of training loss during training. 
- **validation_losses.png**: plot of validation loss during training. 
- **spot** folder: the fitted SPOT objects for dynamic threshold control, one per feature plus the global one. This folder is absent when the `epsilon` method is used for threshold control.

## Prediction  

The prediction folder stores an output JSON file for each time a prediction is run specifying the number of the use case and a timestamp indicating when was run. Each run would generate two files as output, one file having the predicted data for all the data points and the other having the predicted data only for the points which were predicted as anomalies.

- **uc-{use_case}_predicted_data-{n}_{timestamp}.json** 
This file contains predicted data for all the points that were used for prediction, and flags them as anomalies or not. 

- **uc-{use_case}_predicted_anomalies_data-{n}_{timestamp}.json**
This files contains the anomalies detected during a prediction run. 

The contents of both of these files would be in a similar format only varying in the anomaly flag being true or false. The `uc-{use_case}_predicted_anomalies_data-{n}_{timestamp}.json` file contains all the points that have the `is_anomaly` flag `true`, whereas `uc-{use_case}_predicted_data-{n}_{timestamp}.json` would have points with `is_anomaly` flag `true` and `false` both. 

- **spot** folder: the fitted SPOT objects for dynamic threshold control, one per feature plus the global one. This folder is absent when the `epsilon` method is used for threshold control. This object is used for online prediction.
 
For a detailed example we refer to the [ADBox Result Visualizer Notebook](/siem_mtad_gat/frontend/viznotebook/result_visualizer_uc_6.ipynb).