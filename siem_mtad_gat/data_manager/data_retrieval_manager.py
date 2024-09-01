import os
import pickle
import threading
import numpy as np
import torch
import json 
import pandas as pd 
import siem_mtad_gat.settings as settings
import logging
import os
os.makedirs(settings.OUTPUT_LOGS, exist_ok=True)
logging.basicConfig(filename=settings.LOGGING_FILE_NAME.format(name=__name__), format=settings.DEFAULT_LOGGING_FORMAT) 
logger = logging.getLogger(__name__)
logger.setLevel(settings.DEFAULT_LOGGING_LEVEL) 


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
                logging.error(f"Model file '{model_path}' does not exist.")
        
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
                logging.error(f"Model file '{model_path}' does not exist.")

            model.load_state_dict(torch.load(model_path, map_location=device))
            print(f"Model loaded from {model_path}.")
            

    
    
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
                logging.error(f"No configurations found for the detector: {self.path}")

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
            logging.error(f"The folder {predict_storage_folder} does not exist.")
            print(f"The folder {predict_storage_folder} does not exist.")
            return 
        
        files = [f for f in os.listdir(predict_storage_folder) if os.path.isfile(os.path.join(predict_storage_folder, f))]
        
        if not files:
            logging.error(f"The folder {predict_storage_folder} does not contain any files.")
            print(f"The folder {predict_storage_folder} does not contain any files.") 
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
                        logging.error(f"Error reading {file_path}: {e}")
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
                logging.error(f"Summary file not found at {summary_path}.")

    def retrieve_training_outputs(self):
        """
        Retrieve the training and test predictions from pickle files.

        :return: Tuple containing DataFrames for training and test predictions.
        """
        with self._semaphore:
            output_folder_path = settings.TRAINING_STORAGE_FOLDER.format(id=self.detector_id)
            train_output_path = settings.TRAIN_OUTPUT_PKL_FILE_PATH.format(id=self.detector_id) 
            test_output_path = settings.TEST_OUTPUT_PKL_FILE_PATH.format(id=self.detector_id) 

            if os.path.exists(train_output_path) and os.path.exists(test_output_path):
                train_pred_df = pd.read_pickle(train_output_path)
                test_pred_df = pd.read_pickle(test_output_path)
                print(f"Training and test outputs retrieved from {output_folder_path}.")
                return train_pred_df, test_pred_df
            else:
                logging.error("Training or test output files not found.")

    def retrieve_training_config(self):
        """
        Retrieve the training config dictionary from the JSON file.

        :return: Dictionary containing training config information.
        """
        with self._semaphore:
            training_config_path = settings.TRAINING_CONFIG_FILE_PATH.format(id=self.detector_id)
            if os.path.exists(training_config_path):
                with open(training_config_path, "r") as f:
                    training_config = json.load(f)
                print(f"Training config retrieved from {training_config_path}.")
                return training_config
            else:
                #raise FileNotFoundError(f"Training config file not found at {training_config_path}.")
                logging.error(f"Training config file not found at {training_config_path}.")
    
    def load_spot(self, feature:int = -1,file_ext="pkl"):
            with self._semaphore: 
                spot_storage_folder = settings.SPOT_TRAIN_STORAGE_FOLDER.format(id=self.detector_id)
                # Check if the folder exists
                if not os.path.exists(spot_storage_folder):
                    logging.error(f"Spot trained folder not found at {spot_storage_folder} .")

                
                if feature==-1: feature='global'

                if file_ext=="pkl":
                    #load full spot object as pickle file
                    spot_path = settings.SPOT_TRAIN_FILE_PATH.format(id=self.detector_id,feature=feature,ext=file_ext) 
                    with open(spot_path, "rb") as f:
                        spot=pickle.load(f)
                elif file_ext=="json":
                    #load attributes only from json file
                    spot_path = settings.SPOT_TRAIN_FILE_PATH.format(id=self.detector_id,feature=feature,ext=file_ext) 
                    with open(spot_path, "r") as f:
                        spot=json.load(f)               
                    for k in spot: 
                        v=spot[k]
                        if isinstance(v, list) and all([isinstance(x,float) for x in v]): spot[k]=np.asarray(v,dtype=np.float32)
                else:
                    logging.exception(f"Invalide file extension for spot object")
                logging.info(f"Spot object {feature} loaded.")
                
                return spot
            
    def load_preprocessing_scaler(self):

        with self._semaphore: 
            scaler_path = settings.SCALER_FILE_PATH.format(id=self.detector_id) 
            with open(scaler_path, "rb") as f:
                scaler=pickle.load(f)
            logging.info(f"Scaler for preprocessing loaded from {scaler_path}.")
            return scaler

    @classmethod
    def destroy_instance(cls):
        cls._instance = None
    


   