# Data transformation

Row data ingested from Wazuh, or any other source must be cleaned and prepared to be fed to the machine learning model.

This is automatically done by the [Training pipeline](./engine.md#training-pipeline) and the [Prediction pipeline](./engine.md#prediction-pipeline).

Data undergo to three main kind of transformation:
- data type adjustment
- aggregation
- preprocessing

### DataTypeTransformer

The DataTypeTransformer processes raw data into a format suitable for analysis or training through machine learning algorithms. The transformation applied is done according to a predefined back-end configuration file.

### DataAggregator

The DataAggregator extracts and aggregates features from time-series data based granularity and aggregation methods specified in by the current [use case](./use_case.md). It method may be call as part of the preprocessing.

### DataPreprocessor

The DataPreprocessor operates all the transformations that are strictly part of the ML preprocessing, including feature extraction and possibly aggregation, as specified in by the current [use case](./use_case.md).

Below the sequence diagram of preprocessing main method.

```mermaid
sequenceDiagram

	participant p0 as Caller:ad_engine/mtad_gat/ad_engine.py
  participant p1 as DataPreprocessor.preprocess():data_transformer.py
  participant p2 as DataAggregator:data_transformer.py
  participant p4 as DataPreprocessor.split_data:data_transformer.py
	participant p5 as DataPreprocessor.normalize_data:data_transformer.py
	participant p6 as MinMaxScaler:sklearn.preprocessing
  participant p3 as data_storage_manager:manager/data_storage_manager.py
	participant p7 as DataRetrievalManager:manager/data_retrieval_manager.py


	activate p3
	activate p7
	p0 ->>+ p1: preprocess(input_data,training_request, stateful, caller) 
	p1 ->> p1: get feature_list
	alt aggregate is True
	p1 ->>+ p2:  aggregate_data(input_data, input_config.get(<br>"aggregation_config"))
	p2 -->>- p1: : return input_data
	else
	p1 ->> p1: Exception
	end


	alt stateful is True
	p1 ->> +p3:  save_input_data(input_data, True, True, caller)
	deactivate p3
	end


	%% split
	p1 ->>+ p4:  split_data(input_data, test_split)
	p4 -->>- p1: : return train_data, test_data

	%%retrieve scaler
	alt caller is "predict"
	p1 ->> +p7: get_scaler()
	p7 -->>- p1: scaler
	else 
	p1 -->>p1: scaler = None
	end
	%% Normalize
	p1 ->>+ p5:  normalize_data(train_data,scaler=scaler)
	p5 ->> p5: input_data as np.asarray (dtype=np.float32)
	p5 ->> p5: apply nan_to_num
	alt scaler is None
	p5 ->> +p6 : instantiate scaler
	p6 ->> p6: fit(train_data)
	end
	p5 ->> p6: transform(train_data)
	p6 -->> p5: return train_data 

	p5 -->>- p1: : return train_data,train_scaler
	p1 ->>+ p5:  normalize_data(test_data,scaler=train_scaler)
	p5 ->> p5: input_data as np.asarray (dtype=np.float32)
	p5 ->> p5: apply nan_to_num
	p5 ->> p6: transform(test_data)
	p6 -->> -p5: return test_data 
	p5 -->>- p1: : return test_data,scaler

	%% store scaler
	alt caller is "train"
	p1 ->> +p3:  save_scaler(train_scaler)
	deactivate p3
	end

	p1 ->>- p0 : return train_data, test_data, train_stamps, test_stamps, column_names
	deactivate p3
	deactivate p7
```