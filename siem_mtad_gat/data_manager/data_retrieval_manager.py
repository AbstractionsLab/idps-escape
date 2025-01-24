import os
import pickle
import threading
from typing import Tuple
import numpy as np
import torch
import json 
import pandas as pd 
 
from siem_mtad_gat.data_manager import *

from siem_mtad_gat.mtad_gat_pytorch.spot import SPOT
from siem_mtad_gat.commons import EscapeError, EscapeInfo

"""
import logging
import os
os.makedirs(settings.OUTPUT_LOGS, exist_ok=True)
logging.basicConfig(filename=settings.LOGGING_FILE_NAME.format(name=__name__), format=settings.DEFAULT_LOGGING_FORMAT) 
logger = logging.getLogger(__name__)
logger.setLevel(settings.DEFAULT_LOGGING_LEVEL) 
"""



class DataRetrievalManager:
    """
    DataRetrievalManager class to handle retrieval of folders, JSON files, and model training outputs for detectors 
    with proper concurrency control and singleton design pattern.
    """
    
    # Semaphore to prevent concurrent access to the sensitive resource
    _semaphore = threading.Semaphore()
    
    # Singleton instance
    _instance = None


    def __new__(cls, *args, **kwargs):
        """
        Ensure only one instance of DataRetrievalManager exists (Singleton Pattern).
        """
        if cls._instance is None: 
            if args:  
                cls._instance = super(DataRetrievalManager, cls).__new__(cls) 
                cls._instance._initialize(args[0]) 
            else: 
                raise ValueError("Missing detector id ")
        return cls._instance

    def _initialize(self, detector_id: str): 
     
        """
        Initialize the DataRetrievalManager instance with a unique UUID and path.

        :param detector_id: UUID object representing the unique identifier of the detector.
        """ 
        self.detector_id = detector_id
        self.path = settings.DETECTOR_FOLDER.format(id=self.detector_id) 

             
    def model_path(self):
        """
        Return the path to model.pt file within the UUID folder.

        :return: model path.
        :raises FileNotFoundError: If model directory or model.pt file does not exist.
        """
        model_path = settings.MODEL_FILE_PATH.format(id=self.detector_id) 
        
        with self._semaphore:
            if not os.path.exists(model_path):
                raise EscapeError(f"Model file '{model_path}' does not exist.",logger)
        
        return model_path
    
    def load_model(self, model,  device:str = "cpu"):
        """
        Load the model parameters from the specified file within the UUID folder.

        :return: The loaded model.
        :raises FileNotFoundError: If model directory or model.pt file does not exist.
        """
        model_path = settings.MODEL_FILE_PATH.format(id=self.detector_id) 
        
        with self._semaphore:
            if not os.path.exists(model_path):
                raise EscapeError(f"Model file '{model_path}' does not exist.",logger)

            model.load_state_dict(torch.load(model_path, map_location=device))
            EscapeInfo(f"Model loaded from {model_path}.",logger)
            

    
    
    def retrieve_detector_parameters(self):
        """
        Retrieve data from the detector_input_parameters.json file for the specified detector.

        :return: Dictionary containing data from the detector_input_parameters.json file.
        """
        
        detector_data = {}
        param_file_path = settings.DETECTOR_INPUT_PARAMETERS_FILE_PATH.format(id=self.detector_id)
        with self._semaphore: 
            if os.path.exists(param_file_path):
                with open(param_file_path, 'r') as f:
                    detector_data = json.load(f) 
            else: 
                raise EscapeError(f"No configurations found for the detector: {self.path}",logger)

            return detector_data 
    
    
    def retrieve_predict_output(self):
        """
        Retrieve combined data from all JSON files in the PREDICTION_STORAGE_FOLDER
        for the specified detector.

        :return: Dictionary containing combined data from all JSON files.
        """
        
        predict_output = []
        predict_storage_folder = settings.PREDICTION_STORAGE_FOLDER.format(id=self.detector_id)
        
        if not os.path.exists(predict_storage_folder):
            raise EscapeError(f"The folder {predict_storage_folder} does not exist.",logger)

        
        files = [f for f in os.listdir(predict_storage_folder) if os.path.isfile(os.path.join(predict_storage_folder, f))]
        
        if not files:
            raise EscapeError(f"The folder {predict_storage_folder} does not contain any files.",logger)
            #print(f"The folder {predict_storage_folder} does not contain any files.") 
            return 
        with self._semaphore:
            for file_name in files:
                file_path = os.path.join(predict_storage_folder, file_name)
                if file_name.endswith('.json'):
                    try:
                        with open(file_path, 'r') as f:
                            file_data = json.load(f)
                            predict_output.append(file_data)
                    except Exception as e:
                        raise EscapeError(f"Error reading {file_path}: {e}",logger)
        return predict_output
     
     
    
    def retrieve_summary(self):
        """
        Retrieve the summary dictionary from the JSON file.

        :return: Dictionary containing summary information.
        """
        with self._semaphore:
            summary_path = settings.SUMMARY_FILE_PATH.format(id=self.detector_id) 
            if os.path.exists(summary_path):
                with open(summary_path, "r") as f:
                    summary = json.load(f)
                print(f"Summary retrieved from {summary_path}.")
                return summary
            else:
                raise EscapeError(f"Summary file not found at {summary_path}.",logger)

    def retrieve_training_outputs(self) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Retrieve the training and test predictions from pickle files.

        :return: Tuple containing DataFrames for training and test predictions.
        """
        with self._semaphore:
            output_folder_path = settings.TRAINING_STORAGE_FOLDER.format(id=self.detector_id)
            train_output_path = settings.TRAIN_OUTPUT_PKL_FILE_PATH.format(id=self.detector_id) 
            test_output_path = settings.TEST_OUTPUT_PKL_FILE_PATH.format(id=self.detector_id) 

            if os.path.exists(train_output_path) and os.path.exists(test_output_path):
                train_pred_df:pd.DataFrame = pd.read_pickle(train_output_path)
                test_pred_df:pd.DataFrame = pd.read_pickle(test_output_path)
                EscapeInfo(f"Training and test outputs retrieved from {output_folder_path}.",logger)
                return train_pred_df, test_pred_df
            else:
                raise EscapeError("Training or test output files not found.",logger)

    def retrieve_training_config(self) -> dict:
        """
        Retrieve the training config dictionary from the JSON file.

        :return: Dictionary containing training config information.
        """
        with self._semaphore:
            training_config_path = settings.TRAINING_CONFIG_FILE_PATH.format(id=self.detector_id)
            if os.path.exists(training_config_path):
                with open(training_config_path, "r") as f:
                    training_config : dict = json.load(f)
                print(f"Training config retrieved from {training_config_path}.")
                return training_config
            else:
                #raise FileNotFoundError(f"Training config file not found at {training_config_path}.")
                raise EscapeError(f"Training config file not found at {training_config_path}.",logger)
            return {}
    
    def load_spot_pkl(self, feature:int = -1,caller:str=settings.CALLER_TRAIN) -> SPOT:
        """
        Loads spot object from .pkl file
        Expected file name: see setting.SPOT_TRAIN_FILE_PATH.

        Args. 
            feature (int): feature number. If -1, takes global distribution.

        Returns:
            SPOT : instance of SPOT corresponding to input feature
        """
        with self._semaphore: 
                
                if feature==-1: feature='global'  # type: ignore
                paths={
                    settings.CALLER_OFFLINE: settings.SPOT_TRAIN_FILE_PATH.format(id=self.detector_id,feature=feature,ext='pkl'),
                    settings.CALLER_ONLINE: settings.SPOT_ONLINE_FILE_PATH.format(id=self.detector_id,feature=feature,ext='pkl')
                    }
                folder_paths={
                    settings.CALLER_OFFLINE: settings.SPOT_TRAIN_STORAGE_FOLDER.format(id=self.detector_id),
                    settings.CALLER_ONLINE: settings.SPOT_ONLINE_STORAGE_FOLDER.format(id=self.detector_id)
                    }
                spot_storage_folder = folder_paths.get(caller)
                # Check if the folder exists
                if not os.path.exists(spot_storage_folder):
                    raise EscapeError(f"Spot trained folder not found at {spot_storage_folder} .",logger)

                #load full spot object as pickle file
                spot_path = paths.get(caller)
                with open(spot_path, "rb") as f:
                        spot_obj: SPOT=pickle.load(f)

                EscapeInfo(f"Spot object {feature} loaded.",logger)
                
                return spot_obj
            
    def load_spot_json(self, feature:int = -1,caller:str=settings.CALLER_TRAIN) ->  dict :
        """
        Loads spot attributes dictionary from json file
        Expected file name: see setting.SPOT_TRAIN_FILE_PATH.

        Args. 
            feature (int): feature number. If -1, takes global distribution.

        Returns:
            dict : SPOT arguments' dictionary
        """
        with self._semaphore:
            if feature==-1: feature='global'  # type: ignore
            paths={
                    settings.CALLER_OFFLINE: settings.SPOT_TRAIN_FILE_PATH.format(id=self.detector_id,feature=feature,ext='pkl'),
                    settings.CALLER_ONLINE: settings.SPOT_ONLINE_FILE_PATH.format(id=self.detector_id,feature=feature,ext='pkl')
                    }
            folder_paths={
                    settings.CALLER_OFFLINE: settings.SPOT_TRAIN_STORAGE_FOLDER.format(id=self.detector_id),
                    settings.CALLER_ONLINE: settings.SPOT_ONLINE_STORAGE_FOLDER.format(id=self.detector_id)
                    } 
            spot_storage_folder = folder_paths.get(caller,caller)
            # Check if the folder exists
            if not os.path.exists(spot_storage_folder):
                raise EscapeError(f"Spot trained folder not found at {spot_storage_folder} .",logger)



            #load attributes only from json file
            spot_path = paths.get(caller,"")
            with open(spot_path, "r") as f:
                    spot: dict=json.load(f)               
            for k in spot: 
                    v=spot[k]
                    if isinstance(v, list) and all([isinstance(x,float) for x in v]): spot[k]=np.asarray(v,dtype=np.float32)
                
            EscapeInfo(f"Spot dictionary {feature} loaded.",logger)    
            return spot    

            
    def load_preprocessing_scaler(self):
        """
        Retrieves data scaler from preprocessing 
        """
        with self._semaphore: 
            scaler_path: str = settings.SCALER_FILE_PATH.format(id=self.detector_id) 
            with open(scaler_path, "rb") as f:
                scaler=pickle.load(f)
            EscapeInfo(f"Scaler for preprocessing loaded from {scaler_path}.",logger)
            return scaler

    @classmethod
    def destroy_instance(cls):
        cls._instance = None
    


   