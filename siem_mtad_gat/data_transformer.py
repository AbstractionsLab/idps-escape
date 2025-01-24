
import json
import pandas as pd
import numpy as np
import logging
from typing import * 
from sklearn.preprocessing import MinMaxScaler  

from siem_mtad_gat.commons import EscapeError, EscapeWarning
import siem_mtad_gat.settings as settings
import siem_mtad_gat.config_manager.config_keys as keys
from siem_mtad_gat.data_manager.data_storage_manager import DataStorageManager 
from siem_mtad_gat.data_manager.data_retrieval_manager import DataRetrievalManager

import logging
import siem_mtad_gat.settings as settings

logger = logging.getLogger(__name__)
logger.setLevel(settings.DEFAULT_LOGGING_LEVEL)

AGGREGATION_METHODS_MAP: dict[str, str] = {
            'average': 'mean',
            'count': 'count',
            'sum': 'sum',
            'min': 'min',
            'max': 'max'
        }

TIMESTAMP:str='timestamp'

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
            columns_dict: dict = {col_name: dtype for col_name, dtype in config_data[keys.UC_COLUMNS].items()} 
        
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
                    raise EscapeError(f"Unrecognized data type for column '{col}': {dtype}") 
                
        
        # Rename _id column to document_id
        if '_id' in df.columns:
            df: pd.DataFrame = df.rename(columns={'_id': 'document_id'}) 
            
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
            raise EscapeWarning(f"Error converting column '{series.name}' to int: {e}")
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
            raise EscapeWarning(f"Error converting column '{series.name}' to float: {e}",logger)
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
            raise EscapeError(f"Error converting column '{series.name}' to datetime: {e}",logger)
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
            raise EscapeError(f"Error converting column '{series.name}' to bool: {e}",logger)
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
            raise EscapeError(f"Error converting column '{series.name}' to string: {e}",logger)
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


        # Select columns that are of type int, float, Int64, or Float64, and ensure TIMESTAMP column is included
        filtered_df: pd.DataFrame = training_data.select_dtypes(include=['int', 'float', 'Int64', 'Float64']).copy()
        filtered_df[TIMESTAMP] = training_data[TIMESTAMP]

        # Define aggregation methods


        # Extract granularity from the config
        granularity = config.get(keys.UC_GRANULARITY)
        if not granularity:
            raise ValueError(f"The configuration must include a {keys.UC_GRANULARITY} key.")

        # Extract feature-specific aggregation methods from the config
        features_methods = config.get(keys.UC_FEATURES)
        if not features_methods:
            raise ValueError(f"The configuration must include a {keys.UC_FEATURES} key with feature-specific aggregation methods.")

        # Check if TIMESTAMP column is present
        if TIMESTAMP not in training_data.columns:
            raise ValueError(f"The input DataFrame must contain a {TIMESTAMP} column.")


        # Set the timestamp column as the index
        training_data.set_index(TIMESTAMP, inplace=True) 

        # Initialize a list to store resampled data frames
        resampled_data_frames = []

        # Iterate over each feature in the configuration
        for feature, methods in features_methods.items(): 
            for method in methods:
                try: 
                    # Check if the feature exists in the data
                    if feature not in training_data.columns:
                        raise ValueError(f"Feature '{feature}' does not exist in the data.") 

                    if method not in AGGREGATION_METHODS_MAP:
                        raise ValueError(f"Invalid aggregation method '{method}' for feature '{feature}'. Choose from {list(AGGREGATION_METHODS_MAP.keys())}.")
        
                    # Resample and aggregate the feature based on the specified method
                    resampled_col = training_data[feature].resample(granularity).agg(AGGREGATION_METHODS_MAP[method]) 
                    # Rename the column
                    resampled_col = resampled_col.rename(f"{feature}_{method}") 
                    if not resampled_col.empty:
                        resampled_data_frames.append(resampled_col) 
                except Exception as e:
                    raise EscapeError(f"Cannot aggregate feature '{feature}': {e}")
                    print(f"Cannot aggregate feature '{feature}'.")
            

        # Check if there are objects to concatenate
        if resampled_data_frames: 
            # Combine all resampled features into one DataFrame 
            aggregated_data = pd.concat(resampled_data_frames, axis=1)
        else:
            # Handle case where no objects to concatenate 
            raise EscapeError("No data to concatenate.",logger)
            print("No data returned after aggregation.")
            return 
            #raise ValueError("No data to concatenate.")
    
                
        # Conditionally pass padding_value if it is not passed 
        if config.get('padding_value') is not None:
            aggregated_data = DataAggregator.handle_null_values(aggregated_data, config.get(keys.UC_FILL_NA), config.get(keys.UC_PADDING))
        else:
            aggregated_data = DataAggregator.handle_null_values(aggregated_data, config.get(keys.UC_FILL_NA))

        return aggregated_data
   


    @staticmethod
    def handle_null_values(dataframe: pd.DataFrame, fill_NA_method: str = 'Zero', padding_value: float | None= None) -> pd.DataFrame:
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
                   input_config: dict[str, str|dict|list|bool], 
                   test_split: float = 0.3, 
                   normalize: bool = True, 
                   stateful: bool = False, 
                   caller: str | None= None) -> Tuple[np.ndarray,np.ndarray|None,pd.Index,pd.Index,pd.Index]:
        """preprocess data according to input configuration

        Args:
            input_data (pd.DataFrame): data to be preprocessed
            input_config (dict): dictionary of configuration. We assume the dictionary
                contains:
                 - the features' list under the key "columns"
                 - the boolean key "aggregation" (True if time series extraction needed)
                 - if "aggregation" value is True, the configuration of
                 aggregation as value corresponding to the key "aggregation_config".
            test_split (float, optional): the train/test split. Defaults to 0.3.
            normalize (bool, optional): if data normalization is applies. Defaults to True.
            stateful (bool, optional): if data input data are stored wi. Defaults to True.
            caller (str, optional): the pipeline calling the preprocessing.
                        This shall be either settings.CALLER_TRAIN or settings.CALLER_PREDIC.


        Returns:
            tuple[pd.DataFrame,pd.DataFrame,pd.Index,pd.Index]: 
                (train data, test data, train data timestamps, test timestamps)
        """

        # Extract keys from "features" and convert to a list 
        features_list : list= input_config.get(keys.UC_COLUMNS,[])
            
        # It should always fetch timestamp 
        features_list.append(TIMESTAMP)

        #Here will go the encoding for categorical features
        #TBD

        # Check and convert aggregation to boolean if necessary (if it is not a boolean )
        if not isinstance(input_config.get(keys.UC_AGGREGATION), bool): 
            input_config[keys.UC_AGGREGATION] = True if input_config.get(keys.UC_AGGREGATION, "true").lower() == 'true' else False

            # Use the value of aggregation to decide if data needs to be aggregated 
            # If it is true then aggregate the data otherwise don't    
        if input_config.get(keys.UC_AGGREGATION): 

                aggregation_config: dict=input_config.get(keys.UC_AGGREGATION_CONFIG,{})
                if keys.UC_FEATURES in  aggregation_config:
                    input_data = DataAggregator.aggregate_data(input_data, aggregation_config)
                else: 
                    raise ValueError(f"No or invalid {keys.UC_FEATURES} found in {keys.UC_AGGREGATION_CONFIG}")
        else: 
            #TBD : Feature extraction for non aggregated data TBD
            raise NotImplementedError("Non-aggregated features under development")
        
        if input_data is None: 
            return  
        
        data_storage_manager = DataStorageManager() 
        if stateful:
            data_storage_manager.save_input_data(input_data, True, True, caller)

       
        
        # Split the input data in train and test data where size of test chunk is floor(split * size_of_input_data)     
        train_data, test_data = DataPreprocessor.split_data(input_data, test_split)

        # Store timestamps for later mapping (assuming timestamp is used as index!)
        train_stamps: pd.Index = train_data.index
        test_stamps:  pd.Index = test_data.index
        column_names = train_data.columns
        
        # Transform the dataframe entries in numpy
        # This it is useful to later transform the input in torch tensors

        if caller==settings.CALLER_PREDIC:
            data_retrieval_manager=DataRetrievalManager()
            scaler=data_retrieval_manager.load_preprocessing_scaler()
        else:
            scaler=None

        if normalize:
            train_data,train_scaler=DataPreprocessor.normalize_data(train_data,scaler)
            if test_data.shape[0]!=0 : test_data, _=DataPreprocessor.normalize_data(test_data,train_scaler)
            if caller==settings.CALLER_TRAIN:
                data_storage_manager.save_preprocessing_scaler(train_scaler)
        else: 
            train_data =  np.asarray(train_data, dtype=np.float32)
            if test_data.shape[0]!=0 : test_data=np.asarray(test_data,dtype=np.float32)
        
        if stateful and caller==settings.CALLER_PREDIC:
            data_storage_manager.save_preprocessed_data(pd.DataFrame(train_data))


        return train_data, test_data, train_stamps, test_stamps, column_names 
        
    
    @staticmethod
    def normalize_data(in_data : pd.DataFrame, scaler=None) -> tuple[np.ndarray[Any, Any] | Any, MinMaxScaler | Any]: 
        ## normalize_data functions from mtad_gat_pytorch.utils
        data = np.asarray(in_data, dtype=np.float32)
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
                raise EscapeWarning("No data to be split for preprocessing.",logger)
                return 
        raise NotImplementedError(f"Preprocessing for non time-series not implemented")