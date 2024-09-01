import json
import siem_mtad_gat.settings as settings
from datetime import datetime, timedelta

import logging

import os
os.makedirs(settings.OUTPUT_LOGS, exist_ok=True)
logging.basicConfig(filename=settings.LOGGING_FILE_NAME.format(name=__name__), format=settings.DEFAULT_LOGGING_FORMAT)
logger = logging.getLogger(__name__)
logger.setLevel(settings.DEFAULT_LOGGING_LEVEL)

""" The config manager include the implementation of all the
classes use to complete/get the configuration file. E.g.. complete the config files for learning operation
such as training and predicting."""

# TO-DO: add logging

class TrainConfigManager: 
    """Training configuration manager

    Attributes:
        config_path (str): 
            The file path to the custom configuration file.
        train_config (dict or None): 
            The training configuration dictionary. Defaults to None.
        default_config_path (str): 
            The path for the file containing the default configuration arguments and types.

    Methods: 
        get_full_config    
    """
    def __init__(self, default_config_path:str = settings.MTAD_GAT_CONFIG_TRAINING_DEFAULT): 
        self.default_config_path=default_config_path 
        self.default_detector_input_config = settings.DEFAULT_DETECTOR_INPUT_CONFIG

    def get_full_config(self, input_config: json) -> dict: 
        """load input configuration dictionary and complete missing values with default configuration.

        Returns:
            dict: the configuration args for the training
        """

        try: 
           with open(self.default_config_path, "r") as file:
               default_config=json.load(file)  
        except:       
            raise Exception("train_config_default_args.json does not exist.")
        
        train_config={}
        #for each parametersnecessary for the training, we get the input value if available, the default one otherwise.
        for key,default in default_config.items():
            train_config[key]= input_config.get(key, default.get("default")) 
            if type(train_config[key]).__name__ not in [default.get("type"), 'NoneType'] : raise Exception(f"TypeError: {key} expected type is {default_config[key]['type']}!") # for floats ex. use 3.0 not 3

        logger.info(train_config)
        return train_config


