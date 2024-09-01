import pandas as pd
import numpy as np
import logging
from siem_mtad_gat.data_manager.data_retrieval_manager import DataRetrievalManager
import siem_mtad_gat.settings as settings
import json
from sklearn.preprocessing import MinMaxScaler  
from typing import * 
from siem_mtad_gat.data_manager.data_storage_manager import DataStorageManager 
import os
os.makedirs(settings.OUTPUT_LOGS, exist_ok=True)
logging.basicConfig(filename=settings.LOGGING_FILE_NAME.format(name=__name__), format=settings.DEFAULT_LOGGING_FORMAT)
logger = logging.getLogger(__name__)
logger.setLevel(settings.DEFAULT_LOGGING_LEVEL) 


class DataTypeTransformer: 
    @staticmethod
    def transform_data_types(raw_data, columns_config_path : str) -> pd.DataFrame: #convert_data_types  
        """
        Processes raw data into a format suitable for analysis or training through machine learning algorithms.

        Parameters
        ----------
        raw_data : any
            The raw data that needs to be prepared and cleaned. 
        

        Returns
        -------
        prepared_data : pd.DataFrame 
            The prepared, cleaned and aggregated data ready for machine learning algorithms.
        """ 
        
        # The data is in JSON format, so it first need to be normalized into a pandas dataframe 
        df = pd.json_normalize(raw_data)  
        
        # Rename columns by removing '_source'
        df.columns = [col.replace('_source.', '') for col in df.columns]  

        # The config file contains the dictionary of columns and their specified datatypes that need to be converted

        with open(columns_config_path, 'r') as file:
            config_data = json.load(file) 
            columns_dict = {col_name: dtype for col_name, dtype in config_data['columns'].items()} 
        
        # Drop columns not in the columns_info list and remove the _source word from them 
        df = df[[col for col in columns_dict if col in df.columns]]   

        # Change column datatypes if they exist in the DataFrame 
        # Iterate through columns and convert their datatypes 
        for col, dtype in columns_dict.items():
            if col in df.columns:
                if dtype == 'int':
                    df[col] = DataTypeTransformer.convert_to_int(df[col])
                elif dtype == 'float':
                    df[col] = DataTypeTransformer.convert_to_float(df[col])
                elif dtype == 'datetime':
                    df[col] = DataTypeTransformer.convert_to_datetime(df[col])
                elif dtype == 'bool':
                    df[col] = DataTypeTransformer.convert_to_bool(df[col])
                elif dtype == 'string':
                    df[col] = DataTypeTransformer.convert_to_string(df[col])
                else:
                    logging.error(f"Unrecognized data type for column '{col}': {dtype}") 
                
        
        # Rename _id column to document_id
        if '_id' in df.columns:
            df = df.rename(columns={'_id': 'document_id'}) 
            
        return df

        

    @staticmethod
    def convert_to_int(series):
        """
        Convert series to integer data type.

        Args:
            series (pd.Series): Series to be converted.

        Returns:
            pd.Series: Converted series.
        """
        try:
            return series.replace("NaN", np.nan).astype(pd.Float64Dtype()).astype(pd.Int64Dtype())
        except Exception as e:
            logging.error(f"Error converting column '{series.name}' to int: {e}")
            return series

    @staticmethod
    def convert_to_float(series):
        """
        Convert series to float data type.

        Args:
            series (pd.Series): Series to be converted.

        Returns:
            pd.Series: Converted series.
        """
        try:
            return series.replace("NaN", np.nan).astype(pd.Float64Dtype())
        except Exception as e:
            logging.error(f"Error converting column '{series.name}' to float: {e}")
            return series

    @staticmethod
    def convert_to_datetime(series, format=None):
        """
        Convert series to datetime data type.

        Args:
            series (pd.Series): Series to be converted.
            format (str, optional): Date format. Defaults to None.

        Returns:
            pd.Series: Converted series.
        """
        try: 
            # Check if the type is list because some columns had dates in a listed objects like this [2011_08_31] 
            if series.apply(lambda x: isinstance(x, list)).any(): 
                # Extract the first element from the list and replace the list with it 
                series = series.apply(lambda x: x[0] if isinstance(x, list) and x else x)
                series = pd.to_datetime(series, format='%Y_%m_%d', errors='coerce') 
            else: 
                series = pd.to_datetime(series, errors='coerce') 
            return series 
        except Exception as e:
            logging.error(f"Error converting column '{series.name}' to datetime: {e}")
            return series

    @staticmethod
    def convert_to_bool(series):
        """
        Convert series to boolean data type.

        Args:
            series (pd.Series): Series to be converted.

        Returns:
            pd.Series: Converted series.
        """
        try: 
            # Convert string values to boolean in place
            series.replace({'true': True, 'false': False}, inplace=True)
            series.astype(pd.BooleanDtype(), copy=False) 
            return series 
        except Exception as e:
            logging.error(f"Error converting column '{series.name}' to bool: {e}")
            return series

    @staticmethod
    def convert_to_string(series):
        """
        Convert series to string data type.

        Args:
            series (pd.Series): Series to be converted.

        Returns:
            pd.Series: Converted series.
        """
        try:
            return series.astype(pd.StringDtype())
        except Exception as e:
            logging.error(f"Error converting column '{series.name}' to string: {e}")
            return series
    
    


class DataAggregator: 
    """
    A class for extracting and aggregating features from time series data based on a given configuration.

    Methods:
        extract_time_series_features(training_data: pd.DataFrame, config: dict) -> pd.DataFrame:
            Extracts and aggregates features from the time series data based on the provided configuration.
    """ 
    @staticmethod
    def aggregate_data(training_data: pd.DataFrame, config: dict) -> pd.DataFrame:
        """
        Extracts and aggregates features from the time series data based on the provided configuration.
        Aggregates the data based on the granularity and aggregation methods specified in the config.

        Args:
            training_data (pd.DataFrame): The time series data to be processed.
            config (dict): A dictionary that includes the granularity and feature-specific aggregation methods.

        Returns:
            pd.DataFrame: A DataFrame containing aggregated features with the timestamp included.
        """


        # Select columns that are of type int, float, Int64, or Float64, and ensure 'timestamp' column is included
        filtered_df = training_data.select_dtypes(include=['int', 'float', 'Int64', 'Float64']).copy()
        filtered_df['timestamp'] = training_data['timestamp']

        # Define aggregation methods
        aggregation_methods = {
            'average': 'mean',
            'count': 'count',
            'sum': 'sum',
            'min': 'min',
            'max': 'max'
        }

        # Extract granularity from the config
        granularity = config.get('granularity')
        if not granularity:
            raise ValueError("The configuration must include a 'granularity' key.")

        # Extract feature-specific aggregation methods from the config
        features_methods = config.get('features')
        if not features_methods:
            raise ValueError("The configuration must include a 'features' key with feature-specific aggregation methods.")

        # Check if 'timestamp' column is present
        if 'timestamp' not in training_data.columns:
            raise ValueError("The input DataFrame must contain a 'timestamp' column.")


        # Set the timestamp column as the index
        training_data.set_index('timestamp', inplace=True) 

        # Initialize a list to store resampled data frames
        resampled_data_frames = []

        # Iterate over each feature in the configuration
        for feature, methods in features_methods.items(): 
            for method in methods:
                try: 
                    # Check if the feature exists in the data
                    if feature not in training_data.columns:
                        raise ValueError(f"Feature '{feature}' does not exist in the data.") 

                    if method not in aggregation_methods:
                        raise ValueError(f"Invalid aggregation method '{method}' for feature '{feature}'. Choose from {list(aggregation_methods.keys())}.")
        
                    # Resample and aggregate the feature based on the specified method
                    resampled_col = training_data[feature].resample(granularity).agg(aggregation_methods[method]) 
                    # Rename the column
                    resampled_col = resampled_col.rename(f"{feature}_{method}") 
                    if not resampled_col.empty:
                        resampled_data_frames.append(resampled_col) 
                except Exception as e:
                    logging.error(f"Cannot aggregate feature '{feature}': {e}")
                    print(f"Cannot aggregate feature '{feature}'.")
            

        # Check if there are objects to concatenate
        if resampled_data_frames: 
            # Combine all resampled features into one DataFrame 
            aggregated_data = pd.concat(resampled_data_frames, axis=1)
        else:
            # Handle case where no objects to concatenate 
            logging.error("No data to concatenate.")
            print("No data returned after aggregation.")
            return 
            #raise ValueError("No data to concatenate.")
    
                
        # Conditionally pass padding_value if it is not passed 
        if config.get('padding_value') is not None:
            aggregated_data = DataAggregator.handle_null_values(aggregated_data, config.get('fill_na_method'), config.get('padding_value'))
        else:
            aggregated_data = DataAggregator.handle_null_values(aggregated_data, config.get('fill_na_method'))

        return aggregated_data
   


    @staticmethod
    def handle_null_values(dataframe: pd.DataFrame, fill_NA_method: str = 'Zero', padding_value: float = None) -> pd.DataFrame:
        """
        Handle missing values (NaN) in the merged table using specified fill methods.

        Parameters:
        - dataframe (pd.DataFrame): The DataFrame containing potentially missing values.
        - fill_NA_method (str): Method to fill NaN values. Default is 'Linear'.
        Options include: 'Linear', 'Previous', 'Subsequent', 'Zero', 'Fixed'.
        - padding_value (float): Value to use when 'Fixed' method is selected. Required only for 'Fixed' method.

        Returns:
        - pd.DataFrame: DataFrame with NaN values filled according to the specified method.

        Fill Methods:
        - Linear: Fill NaN values by linear interpolation.
        - Previous: Propagate last valid value to fill gaps.
        - Subsequent: Use next valid value to fill gaps.
        - Zero: Fill NaN values with 0.
        - Fixed: Fill NaN values with the specified padding_value.
        """

        if fill_NA_method == 'Linear':
            return dataframe.interpolate(method='linear', limit_direction='both')

        elif fill_NA_method == 'Previous':
            return dataframe.fillna(method='ffill')

        elif fill_NA_method == 'Subsequent':
            return dataframe.fillna(method='bfill')

        elif fill_NA_method == 'Zero':
            return dataframe.fillna(0)

        elif fill_NA_method == 'Fixed':
            if padding_value is None:
                raise ValueError("padding_value must be provided for 'Fixed' fill method.")
            return dataframe.fillna(padding_value)
        else:
            raise ValueError(f"Invalid fill_NA_method: {fill_NA_method}. Options are 'Linear', 'Previous', 'Subsequent', 'Zero', 'Fixed'.")



class DataPreprocessor: 
    @staticmethod
    def preprocess(input_data: pd.DataFrame, 
                   input_config: json, 
                   test_split: float = 0.3, 
                   normalize: bool = True, 
                   stateful: bool = False, 
                   caller: str = None) -> tuple[pd.DataFrame,pd.DataFrame,pd.Index,pd.Index]:  
        """preprocess data according to input configuration

        Args:
            input_data (pd.DataFrame): data to be preprocessed
            input_config (json): dictionary of configuration. We assume the dictionary
                contains:
                 - the features' list under the key "columns"
                 - the boolean key "aggregation" (True if time series extraction needed)
                 - if "aggregation" value is True, the configuration of
                 aggregation as value corresponding to the key "aggregation_config".
            test_split (float, optional): the train/test split. Defaults to 0.3.
            normalize (bool, optional): if data normalistion is applies. Defaults to True.
            stateful (bool, optional): if data input data are stored wi. Defaults to True.


        Returns:
            tuple[pd.DataFrame,pd.DataFrame,pd.Index,pd.Index]: 
                train data, test data, train data timesstamps, test timestamps)
        """

        # Extract keys from "features" and convert to a list 
        features_list = input_config.get("columns")
            
        # It should always fetch timestamp 
        features_list.append("timestamp")

        #Here will go the encoding for categorical features
        #TBD

        # Check and convert aggregation to boolean if necessary (if it is not a boolean )
        if not isinstance(input_config.get("aggregation"), bool): 
            input_config["aggregation"] = True if input_config.get("aggregation", "true").lower() == 'true' else False

            # Use the value of aggregation to decide if data needs to be aggregated 
            # If it is true then aggregate the data otherwise don't    
        if input_config.get("aggregation"): 
                if "features" in input_config["aggregation_config"]: 
                    input_data = DataAggregator.aggregate_data(input_data, input_config.get("aggregation_config"))
                else: 
                    raise ValueError(f"No or invalid features found in aggregation_config")
        else: 
            #TBD : Feature extraction for non aggregated data TBD
            raise NotImplementedError(f"Non-aggregated features under development")
        
        if input_data is None: 
            return  
        
        data_storage_manager = DataStorageManager() 
        if stateful:
            data_storage_manager.save_input_data(input_data, True, True, caller)

       
        
        # Split the input data in train and test data where size of test chunck is floor(split * size_of_input_data)     
        train_data, test_data = DataPreprocessor.split_data(input_data, test_split)

        # Store timestamaps for later mapping (assuming timestamp is used as index!)
        train_stamps = train_data.index
        test_stamps = test_data.index
        column_names = train_data.columns
        
        # Tranform the dataframe entries in numpy
        # This it is useful to later tranforme the input in torch tensors

        if caller=="predict":
            data_retrieval_manager=DataRetrievalManager()
            scaler=data_retrieval_manager.load_preprocessing_scaler()
        else:
            scaler=None

        if normalize:
            train_data,train_scaler=DataPreprocessor.normalize_data(train_data,scaler)
            if test_data.shape[0]!=0 : test_data,_=DataPreprocessor.normalize_data(test_data,train_scaler)
            if caller=="train":
                data_storage_manager.save_preprocessing_scaler(train_scaler)
        else: 
            train_data =  np.asarray(train_data, dtype=np.float32)
            if test_data.shape[0]!=0 : test_data=np.asarray(test_data,dtype=np.float32)
        
        return train_data, test_data, train_stamps, test_stamps, column_names 
        
    
    @staticmethod
    def normalize_data(data : pd.DataFrame, scaler=None): 
        ## normalize_data functions from mtad_gat_pytorch.utils
        data = np.asarray(data, dtype=np.float32)
        if np.any(sum(np.isnan(data))):
            data = np.nan_to_num(data)

        if scaler is None:
            scaler = MinMaxScaler()
            scaler.fit(data)
        data = scaler.transform(data)
        #print("Data normalized")

        return data, scaler
    
    @staticmethod
    def split_data(input: pd.DataFrame,
                   split: float = 0.2, 
                   time_series: bool = True 
                   ) -> tuple[pd.DataFrame,pd.DataFrame]:
        """Split input data in 2 parts (test and train)
        the proportion id floor(split * size_of_input_data) is size of test

        Args:
            input (pd.DataFrame): input data
            split (float, optional): pr. Defaults to 0.2.

        Returns:
            tuple[pd.DataFrame,pd.DataFrame]: train data and test data
        """
        if time_series: 
            if  input is not None:
                size_data,n_features=input.shape
                test_size = int(split * size_data) 
                train_size = size_data - test_size
                return input.iloc[:train_size,:],input.iloc[train_size:,:]
            else: 
                logging.error("No data to be split.")
                print("No data to be split for preprocessing.")
                return 
        raise NotImplementedError(f"Preprocessing for non time-series not implemented")