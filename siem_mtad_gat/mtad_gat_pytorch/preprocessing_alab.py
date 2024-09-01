import json
import pandas as pd
import numpy as np
from os import listdir, makedirs, path
import sys
from data_preparation.time_series_extractor import TimeSeriesExtractor 
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import TimeSeriesSplit
from sklearn.preprocessing import OneHotEncoder
from mtad_gat_pytorch.config_manager import PreprocessConfigManager
import siem_mtad_gat.settings as settings
import logging
import os
os.makedirs(settings.OUTPUT_LOGS, exist_ok=True)
logging.basicConfig(filename=settings.LOGGING_FILE_NAME.format(name=__name__), format=settings.DEFAULT_LOGGING_FORMAT)
logger = logging.getLogger(__name__)
logger.setLevel(settings.DEFAULT_LOGGING_LEVEL)



""" This module contains the Preprocessor class for 
preprocessing time-series ingested from Wazuh indexer
to work within ADBox framework.
"""



class Preprocessor:
    def __init__(self, model_id, preprocessing_config=None):
        self.config = preprocessing_config
        self.aggregated = None
        self.model_id = model_id

    def preprocess(self, input_data : pd.DataFrame, id_data : str = None, test_split : float = 0.3, normalize : bool = True, stateful: bool = False) -> tuple[np.ndarray,np.ndarray] :

        if id_data == None : id_data = self.model_id

        #load config file. If None, load default file.---- This TOBEREPLACED
        config_manager = PreprocessConfigManager(self.config)
        self.config = config_manager.load_config(True)

        # record possible aggration of the files
        self.aggregated = (self.config['granularity'] != None)
    

        #TOBEUPDATED
        assert set(input_data.columns) == (self.config['columns'].keys())

                

        #size_data,n_features=input_data.shape
        train_data,test_data =self._split_data(input_data,test_split)
        # we store the timestamaps for later mapping (assuming timestamp is used as index)
        train_stamps = train_data.index
        test_stamps = test_data.index

        if stateful:
            #create output folder - based on preprocess.py
            output_folder = path.join(settings.INPUT_DATA_STORAGE, id_data) #decide compliance path
            makedirs(output_folder, exist_ok=True)

            pickles=True
            csv=True
            #dump pickle files 
            if pickles:
                input_data.to_pickle(path.join(output_folder, "input" + ".pkl"))
                test_data.to_pickle(path.join(output_folder, "test" + ".pkl"))
                train_data.to_pickle(path.join(output_folder, "train" + ".pkl"))
            if csv:
                input_data.to_csv(path.join(output_folder, "input" + ".csv"))
         
        #we tranform the numbers in numpy so can be tranformed in torch tensors
        if normalize:
            train_data,_=self._normalize_data(train_data)
            print(train_data)
            if test_data.shape[0]!=0 : test_data,_=self._normalize_data(test_data)
        else: 
            train_data =  np.asarray(train_data,dtype=np.float32)
            if test_data.shape[0]!=0 : test_data=np.asarray(test_data,dtype=np.float32)

        return train_data,test_data,train_stamps,test_stamps

    def _normalize_data(self, data : pd.DataFrame, scaler=None): ## normalize_data functions from utils
        print(data)
        data = np.asarray(data, dtype=np.float32)
        if np.any(sum(np.isnan(data))):
            data = np.nan_to_num(data)

        if scaler is None:
            scaler = MinMaxScaler()
            scaler.fit(data)
        data = scaler.transform(data)
        print("Data normalized")

        return data, scaler
    
    def _split_data(self, input : pd.DataFrame, split : float = 0.2) -> tuple[pd.DataFrame,pd.DataFrame]:
        size_data,n_features=input.shape
        test_size = int(split * size_data) 
        train_size = size_data - test_size
        return input.iloc[:train_size,:],input.iloc[train_size:,:]
        
    


