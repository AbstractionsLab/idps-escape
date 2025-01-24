import json
import logging
import yaml
import siem_mtad_gat.settings as settings
import siem_mtad_gat.config_manager.config_keys as keys
from datetime import datetime, timedelta
from siem_mtad_gat.commons import EscapeError, EscapeInfo, logger


import os

from siem_mtad_gat.time_manager import RUNMODE_ERROR, TimeManager

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

    Methods: 
        get_full_config    
    """
    def __init__(self, default_config_path:str = settings.MTAD_GAT_CONFIG_TRAINING_DEFAULT): 
        self.default_config_path: str=default_config_path 

    def get_full_config(self, input_config: dict) -> dict: 
        """load input configuration dictionary and complete missing values with default configuration.

        Args:
            input_config (dict): the config dictionary to be examined and completed

        Returns:
            dict: the configuration args for the training
        """

        try: 
           with open(self.default_config_path, "r") as file:
               default_config: dict=json.load(file)  
        except:       
            raise EscapeError("train_config_default_args.json does not exist.")
        
        train_config={}
        #for each parameters necessary for the training, we get the input value if available, the default one otherwise.
        for key,default in default_config.items():
            train_config[key]= input_config.get(key, default.get(keys.CONFIG_DEFAULT)) 
            if type(train_config[key]).__name__ not in [default.get(keys.CONFIG_TYPE), 'NoneType']:
                raise EscapeError(f"TypeError: {key} expected type is {default_config[key][(keys.CONFIG_TYPE)]}!",log=logger) # for floats ex. use 3.0 not 3

        return train_config

class DetectorConfigManager: 
    def __init__(self, default_detector_id, default_config_path:str = settings.DEFAULT_DETECTOR_INPUT_CONFIG, use_case_number:int|None = None): 
        self.default_config_path:str=default_config_path
        self.uc_n: int | None=use_case_number
        if self.uc_n is not None: self.yaml_file: str = settings.UC_YAML_FILE.format(number=self.uc_n) 
        self.default_id=default_detector_id

    def get_train_config_from_uc_yaml(self) -> None | dict:
        """
        Loads default detector training input configuration from a file, updates specific fields,
        and returns the updated configuration.

        If the key UC_TRAINING is missing in the input uc, it returns None.
        Otherwise, it uses settings.DEFAULT_DETECTOR_INPUT_CONFIG to get the default configuration values,
        when either no use-case number or key values are missing it complete the training configuration dictionary.

        Returns:
            dict: Training configuration dictionary.
        """ 
        # Load default input configuration from file
        with open(self.default_config_path, 'r') as f:
            default_config:dict = json.load(f)
        
        if self.uc_n is not None:
            # Read the yaml file 
            yaml_file: str = self.yaml_file
            if os.path.exists(yaml_file):
                with open(yaml_file, 'r') as f:
                    custom_input:dict[str,str|bool|dict] = yaml.safe_load(f) 
                    
                if keys.UC_TRAINING not in custom_input: 
                    EscapeInfo(f"No training ('{keys.UC_TRAINING}') key found in the custom input",log=logger)
                    return None 
                
                train_custom_input = custom_input.get(keys.UC_TRAINING) 
                if train_custom_input is None: train_custom_input = {} # it can be None even if the keys is in the key list

                #f=lambda k : train_custom_input.get(k,default_config.get(k))
                train_config=self.__get_value_or_default(train_custom_input,default_config,keys.UC_TRAINING_LIST)
            
            else: 
                EscapeInfo(f"{yaml_file} does not exist, default config will be used.")
                #print(f"{yaml_file} does not exist, default config will be used.") 
                f=lambda k : default_config.get(k)
                train_config={k: f(k) for k in keys.UC_TRAINING_LIST}
        else: 
            EscapeInfo(f"No input use-case: a detection with default config will be created.",log=logger)
            #print(f"No input use-case: a detection with default config will be created.") 

            f=lambda k : default_config.get(k)
            train_config={k: f(k) for k in keys.UC_TRAINING_LIST}
        
        # dynamic default args
        if train_config.get(keys.UC_INDEX_DATE) == keys.UC_DEFAULT:
            train_config[keys.UC_INDEX_DATE]=TimeManager.get_index_current_month() #current month
            
        if train_config.get(keys.UC_DISPLAY_NAME) == keys.UC_DEFAULT:
            train_config[keys.UC_DISPLAY_NAME]= self.get_default_detector_name()
        
        if train_config.get(keys.UC_AGGREGATION) is False:
            train_config[keys.UC_AGGREGATION_CONFIG]={}
        
        if train_config.get(keys.UC_AGGREGATION,bool):
                colums=train_config.get(keys.UC_COLUMNS,[])
                fe=list(train_config.get(keys.UC_AGGREGATION_CONFIG,{}).get(keys.UC_FEATURES,{}).keys())
                assert set(colums)==set(fe), EscapeError(f"{keys.UC_COLUMNS} is {colums}, while in {keys.UC_AGGREGATION_CONFIG} there is {fe}")

        return train_config


    def get_predict_config_from_uc_yaml(self):
        """
        Loads default detector prediction input from a file, updates specific fields,
        and returns the updated prediction input.

        Returns:
            dict: Updated prediction input dictionary.
        """ 
        # Load default input configuration from file
        with open(self.default_config_path, 'r') as f:
            default_config:dict = json.load(f)
        
        if self.uc_n is not None:
            # Read the yaml file 
            yaml_file: str = self.yaml_file
            if os.path.exists(yaml_file):
                with open(yaml_file, 'r') as f:
                    custom_input:dict[str,str|bool|dict] = yaml.safe_load(f) 
                    
                if keys.UC_PREDICTION not in custom_input: 
                    EscapeInfo(f"No prediction ('{keys.UC_PREDICTION}') key found in the custom input",log=logger)
                    return None 
                
                predict_custom_input = custom_input.get(keys.UC_PREDICTION)
                if predict_custom_input is None: predict_custom_input = {} 

                f=lambda k : predict_custom_input.get(k,default_config.get(k)) ## get custom value else default

                runmode = f(keys.UC_RUN_MODE)
                runmode = next(m for m in settings.RUN_MODE if m.name.lower() == runmode.lower()) 
                

                match runmode: 
                    # online method do not require to set start and end time
                    case settings.RUN_MODE.HISTORICAL: 
                        predict_config={k: f(k) for k in keys.UC_HISTORICAL_LIST}
                        now=TimeManager.now_str()
                        # dynamic default setting as today
                        if predict_config.get(keys.UC_START_TIME) == keys.UC_DEFAULT:
                            predict_config[keys.UC_START_TIME]= TimeManager.timestamp_to_str(TimeManager.round_unit_timestamp_prior(time=now,granularity='1day'))               
                        if predict_config.get(keys.UC_END_TIME) == keys.UC_DEFAULT:
                            predict_config[keys.UC_END_TIME]= now  

                    case settings.RUN_MODE.BATCH:
                        predict_config= {k: f(k) for k in keys.UC_BATCH_LIST}

                    case settings.RUN_MODE.REALTIME: 
                        predict_config={k: f(k) for k in keys.UC_REALTIME_LIST}
                      

                    # this also check if an invalid runmode is passed
                    case _:
                        logger.error(RUNMODE_ERROR) 
                        raise ValueError(RUNMODE_ERROR)
                    
                predict_config[keys.UC_RUN_MODE] = runmode

                #dynamic default args: detector id    
                if predict_config.get(keys.UC_DETECTOR_ID) == keys.UC_DEFAULT:
                            predict_config[keys.UC_DETECTOR_ID]=self.default_id
                
                if predict_config.get(keys.UC_AGGREGATION,bool):
                    colums=predict_config.get(keys.UC_COLUMNS,[])
                    fe=list(predict_config.get(keys.UC_AGGREGATION_CONFIG,{}).get(keys.UC_FEATURES,{}).keys())
                    assert set(colums)==set(fe), EscapeError(f"{keys.UC_COLUMNS} is {colums}, while in {keys.UC_AGGREGATION_CONFIG} there is {fe}")
                
                
                return predict_config

            else: 
                EscapeInfo(f"{yaml_file} does not exist.",log=logger)
                return None
        else: 
            EscapeInfo("No input use-case: prediction won't be run.",log=logger)
            #print(f"No input use-case: prediction won't be run.") 
            return None


    @staticmethod
    def get_default_detector_name() -> str:
        """
        Returns a string representing a detector name in the format 'detector_<current timestamp>'.

        Returns:
            str: Detector name string.
        """
        current_timestamp = datetime.now(settings.TIMEZONE).strftime(settings.DATE_TIME_FORMAT)
        detector_name = f"detector_{current_timestamp}"
        return detector_name
    
    def __get_value_or_default(self,custom:dict,default:dict,keys_list:list) -> dict:
            f=lambda k : custom.get(k,default.get(k))
            out={}
            for k in keys_list:
                it=f(k)
                if isinstance(it,dict) and k!=keys.UC_FEATURES: it=self.__get_value_or_default(it,default.get(k),list(default.get(k,{}).keys()))
                out[k]=it
            return out
    
