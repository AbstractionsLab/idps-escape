from typing import List, Dict, Union, Any 
import json
import siem_mtad_gat.settings as settings
from datetime import datetime, timedelta, date 
import logging
import os
import yaml 
os.makedirs(settings.OUTPUT_LOGS, exist_ok=True)
logging.basicConfig(filename=settings.LOGGING_FILE_NAME.format(name=__name__), format=settings.DEFAULT_LOGGING_FORMAT)
logger = logging.getLogger(__name__)
logger.setLevel(settings.DEFAULT_LOGGING_LEVEL) 

# TO-REDESIGN (consolidate all dictionary and data frame creation (detector, input config, etc) logic and code into a dedicated, reusable class)
# TO-REDESIGN (see all redesign tags in the ad_engine.py)
# TO-DO (rewrite to remove all hard-coded data frame attributes)

class Detector:
    def __init__(self): 
        self.default_detector_input_config = settings.DEFAULT_DETECTOR_INPUT_CONFIG 
        self._index_date: str 
        self._categorical_features: bool 
        self._columns: List[str] 
        self._aggregation: bool 
        self._aggregation_config: Dict[str, Any] 
        self._fill_na_method: str 
        self._padding_value: int 
        self._granularity: str  
        self._features: Dict[str, List[str]] 
        self._train_config: Dict[str, int] 
        self._display_name: str 

    # Getter and setter for _index_date
    @property
    def index_date(self) -> str:
        return self._index_date
    
    @index_date.setter
    def index_date(self, date: str) -> None:
        self._index_date = date

    # Getter and setter for _categorical_features
    @property
    def categorical_features(self) -> bool:
        return self._categorical_features
    
    @categorical_features.setter
    def categorical_features(self, value: bool) -> None:
        self._categorical_features = value

    # Getter and setter for _columns
    @property
    def columns(self) -> List[str]:
        return self._columns
    
    @columns.setter
    def columns(self, columns: List[str]) -> None:
        self._columns = columns

    # Getter and setter for _aggregation
    @property
    def aggregation(self) -> bool:
        return self._aggregation
    
    @aggregation.setter
    def aggregation(self, value: bool) -> None:
        self._aggregation = value

    # Getter and setter for _aggregation_config
    @property
    def aggregation_config(self) -> Dict[str, Any]:
        return self._aggregation_config
    
    @aggregation_config.setter
    def aggregation_config(self, config: Dict[str, Any]) -> None:
        self._aggregation_config = config

    # Getter and setter for _fill_na_method
    @property
    def fill_na_method(self) -> str:
        return self._fill_na_method
    
    @fill_na_method.setter
    def fill_na_method(self, method: str) -> None:
        self._fill_na_method = method

    # Getter and setter for _padding_value
    @property
    def padding_value(self) -> int:
        return self._padding_value
    
    @padding_value.setter
    def padding_value(self, value: int) -> None:
        self._padding_value = value

    # Getter and setter for _granularity
    @property
    def granularity(self) -> str:
        return self._granularity
    
    @granularity.setter
    def granularity(self, granularity: str) -> None:
        self._granularity = granularity

    # Getter and setter for _features
    @property
    def features(self) -> Dict[str, List[str]]:
        return self._features
    
    @features.setter
    def features(self, features: Dict[str, List[str]]) -> None:
        self._features = features

    # Getter and setter for _train_config
    @property
    def train_config(self) -> Dict[str, int]:
        return self._train_config
    
    @train_config.setter
    def train_config(self, value: Dict[str, int]) -> None:
        self._train_config = value

    # Getter and setter for _display_name
    @property
    def display_name(self) -> str:
        return self._display_name
    
    @display_name.setter
    def display_name(self, value: str) -> None:
        self._display_name = value

        

    def get_detector_training_input(self, 
                                    index_date:str="default", 
                                    display_name:str="default", 
                                    default:bool=True, 
                                    custom_config_file=None):
        """
        Loads default detector training input configuration from a file, updates specific fields,
        and returns the updated configuration.

        Returns:
            dict: Updated training input configuration dictionary.
        """ 
        # Load default training input configuration from file
        with open(self.default_detector_input_config, 'r') as f:
            input_config = json.load(f)
        
        if default == False and custom_config_file != None: 
            # Read the yaml file 
            yaml_file = settings.DRIVER_YAML_FILE.format(name=custom_config_file)
            if os.path.exists(yaml_file):
                with open(yaml_file, 'r') as f:
                    custom_input = yaml.safe_load(f) 
                    
                if 'training' not in custom_input: 
                    logging.info("No training key found in the custom input")
                    return None 
                
                train_custom_input = custom_input['training']

                # Update attributes based on custom input content 
                if index_date == "default": 
                    input_config["index_date"] = self.get_index_date_for_training() if train_custom_input.get("index_date") == "default" else train_custom_input.get("index_date", self.get_index_date_for_training())
                else: 
                    input_config["index_date"] = index_date 
                    
                if display_name == "default": 
                    input_config["display_name"] = self.get_default_detector_name() if train_custom_input.get("display_name") == "default" else train_custom_input.get("display_name", self.get_default_detector_name())
                else: 
                    input_config["display_name"] = display_name  
                    
                    
                input_config["categorical_features"] = (
                    train_custom_input.get("categorical_features")
                    or input_config["categorical_features"]
                ) 
                input_config["columns"] = (
                    train_custom_input.get("columns")
                    or input_config["columns"]
                ) 
                input_config["aggregation"] = (
                    train_custom_input.get("aggregation")
                    or input_config["aggregation"]
                )  
                input_config["categorical_features"] = (
                    train_custom_input.get("categorical_features")
                    or input_config["categorical_features"]
                )   
                # input_config["aggregation_config"] = train_custom_input.get("aggregation_config",  input_config["aggregation_config"])
                input_config["aggregation_config"]["fill_na_method"] = (
                    train_custom_input.get("aggregation_config", {}).get("fill_na_method")
                    or input_config["aggregation_config"]["fill_na_method"]
                ) 
                input_config["aggregation_config"]["padding_value"] = (
                    train_custom_input.get("aggregation_config", {}).get("padding_value")
                    or input_config["aggregation_config"]["padding_value"]
                )  
                input_config["aggregation_config"]["granularity"] = (
                    train_custom_input.get("aggregation_config", {}).get("granularity")
                    or input_config["aggregation_config"]["granularity"]
                ) 
                input_config["aggregation_config"]["features"] = (
                    train_custom_input.get("aggregation_config", {}).get("features")
                    or input_config["aggregation_config"]["features"]
                )  
                input_config["train_config"] = (
                    train_custom_input.get("train_config")
                    or input_config["train_config"]
                )  
                    
            else: 
                print("{yaml_file} does not exist, default config will be used.") 
                input_config["index_date"] = self.get_index_date_for_training() if index_date == "default" else index_date
                input_config["display_name"] = self.get_default_detector_name() if display_name == "default" else display_name
                
        else:    
            input_config["index_date"] = self.get_index_date_for_training() if index_date == "default" else index_date
            input_config["display_name"] = self.get_default_detector_name() if display_name == "default" else display_name
            # input_config["categorical_features"] = self._categorical_features 
            # input_config["columns"] = self.columns 
            # input_config["aggregation"] = self.aggregation 
            # input_config["aggregation_config"] = self.aggregation_config 
            # input_config["aggregation_config"]["fill_na_method"] = self.fill_na_method 
            # input_config["aggregation_config"]["padding_value"] = self.padding_value 
            # input_config["aggregation_config"]["granularity"] = self.granularity 
            # input_config["aggregation_config"]["features"] = self.features  
            # input_config["train_config"] = self.train_config  
            
        
        return input_config
        


    def get_detector_prediction_input(self, 
                                              run_mode=settings.RUN_MODE.HISTORICAL, 
                                              index_date:str="default", 
                                              start_time:str="default", 
                                              end_time:str="default", 
                                              granularity:str=settings.DEFAULT_GRANULARITY, 
                                              window_size:int=settings.DEFAULT_WINDOW_SIZE, 
                                              batch_size:int=settings.DEFAULT_BATCH_SIZE):
        """
        Loads default detector prediction input from a file, updates specific fields,
        and returns the updated prediction input.

        Returns:
            dict: Updated prediction input dictionary.
        """ 

        match run_mode:
            # HISTORICAL MODE 
            case settings.RUN_MODE.HISTORICAL:
                # Define default detector prediction input
                default_detector_prediction_input = {
                        "run_mode" : run_mode.name, 
                        "detector_id": "", 
                        "index_date": self.get_index_date_for_prediction() if index_date == "default" else index_date,
                        "start_time": self.get_fetch_start_time(run_mode) if start_time == "default" else  start_time, 
                        "end_time": self.get_fetch_end_time(run_mode, self.get_end_time(run_mode), granularity, window_size) if end_time == "default" 
                        else self.get_fetch_end_time(run_mode, end_time, granularity, window_size)       
                    }
            
            # BATCH MODE 
            case settings.RUN_MODE.BATCH:
                # Define default detector prediction input
                default_detector_prediction_input = {
                        "run_mode" : run_mode.name, 
                        "detector_id": "", 
                        "index_date": self.get_index_date_for_prediction(),
                        "start_time": self.get_fetch_start_time(run_mode, self.get_end_time(run_mode, granularity, window_size), batch_size, granularity), 
                        "end_time": self.get_fetch_end_time(run_mode)
                        }

            
            # REALTIME MODE 
            case settings.RUN_MODE.REALTIME:
                # Define default detector prediction input
                default_detector_prediction_input = {
                        "run_mode" : run_mode.name, 
                        "detector_id": "", 
                        "index_date": self.get_index_date_for_prediction(),
                        "start_time": self.get_fetch_start_time(run_mode, end_time=self.get_end_time(run_mode, granularity, window_size), granularity=granularity), 
                        "end_time": self.get_fetch_end_time(run_mode)
                        }
                
            case _:
                logging.error("Invalid run mode.")  
        
        # Extract start_time and end_time for validation
        start_time_dt = default_detector_prediction_input["start_time"]
        end_time_dt = default_detector_prediction_input["end_time"]

        # Ensure end_time is greater than start_time
        if end_time_dt <= start_time_dt:
            raise ValueError("End time must be greater than start time.")
        return default_detector_prediction_input   
   
   
   
    def parse_predict_config(self, config_file_name): 
        # Check if the file exists
        yaml_file = settings.DRIVER_YAML_FILE.format(name=config_file_name) 
        if not os.path.exists(yaml_file):
            print(f"Configuration file {yaml_file} does not exist. Using default values.")
            return 'default', 'default', 'default', 'default', 'default', settings.DEFAULT_BATCH_SIZE
    
        with open(yaml_file, 'r') as file:    
            config = yaml.safe_load(file)
            prediction_config = config.get('prediction', {})

            run_mode = prediction_config.get('run_mode') or 'default'
            index_date = prediction_config.get('index_date') or 'default'
            detector_id = prediction_config.get('detector_id') or 'default'
            start_time = prediction_config.get('start_time') or 'default'
            end_time = prediction_config.get('end_time') or 'default'
            batch_size = prediction_config.get('batch_size')
            batch_size = batch_size if batch_size is not None else settings.DEFAULT_BATCH_SIZE  # Ensure batch_size defaults to default value 

        return run_mode, index_date, detector_id, start_time, end_time, batch_size 


    def get_index_date_for_training(self):
        """
        Returns the index date in the format 'YYYY-MM-*' based on the current date.

        It returns the current month and year with date as '*'.

        Returns:
            str: Index date in 'YYYY-MM-*' format.
        """        
        # Return current month and year with '*'
        return  datetime.today().strftime("%Y-%m-*")




    def get_index_date_for_prediction(self):
        """
        Returns the index date in the format 'YYYY-MM-DD' based on the current date.

        It returns the current date.

        Returns:
            str: Index date in 'YYYY-MM-DD' format.
        """        
        # Return today's date in 'YYYY-MM-DD' format
        return datetime.today().strftime(settings.DATE_FORMAT)



    # def get_start_time(self) -> str:
    #     """
    #     Returns the start timestamp of today in the format 'YYYY-MM-DDTHH:MM:SSZ'.

    #     Returns:
    #         str: Start timestamp of today.
    #     """
    #     return date.today().strftime(settings.DATE_TIME_FORMAT)
    
    
    def get_end_time(self, run_mode, granularity=settings.DEFAULT_GRANULARITY, window_size=settings.DEFAULT_WINDOW_SIZE) -> str:
        """
        Calculate the end time based on the run mode, granularity, and window size.

        Args:
            run_mode (Enum): The detection run mode, which can be HISTORICAL, BATCH, or REALTIME.
            granularity (str, optional): The granularity string, e.g., '1min'.
            window_size (int, optional): The window size to multiply by.

        Returns:
            str: The calculated end time in the format 'YYYY-MM-DDTHH:MM:SSZ'.

        Raises:
            ValueError: If granularity or window_size is not provided for BATCH or REALTIME modes.
        """
        match run_mode:
            case settings.RUN_MODE.HISTORICAL:
                # HISTORICAL mode: simply return the current time. 
                return datetime.now(settings.TIMEZONE).strftime(settings.DATE_TIME_FORMAT)

            case settings.RUN_MODE.BATCH:
                # Validate inputs
                if granularity is None or window_size is None:
                    raise ValueError("granularity and window_size must be provided for BATCH mode")
                
                # BATCH mode: calculate the end time as current time minus the detector interval. 
                current_time = datetime.now(settings.TIMEZONE)
                detector_interval = self.get_detector_interval(granularity, window_size)
                end_time = current_time - timedelta(minutes=detector_interval)
                return end_time.strftime(settings.DATE_TIME_FORMAT)

            case settings.RUN_MODE.REALTIME:
                # Validate inputs
                if granularity is None or window_size is None:
                    raise ValueError("granularity and window_size must be provided for REALTIME mode")
                
                # REALTIME mode: calculate the end time as current time minus the detector interval. 
                current_time = datetime.now(settings.TIMEZONE)
                detector_interval = self.get_detector_interval(granularity, window_size)
                end_time = current_time - timedelta(minutes=detector_interval)
                return end_time.strftime(settings.DATE_TIME_FORMAT)

            case _:
                raise ValueError("Invalid run mode.")
            
         
    
    
    def get_batch_interval_in_minutes(self, batch_size=settings.DEFAULT_BATCH_SIZE, granularity=settings.DEFAULT_GRANULARITY):
        """
        Calculate the batch interval in minutes based on batch size and granularity.

        Args:
            batch_size (int): The size of each batch.
            granularity (str or int): The granularity factor, either as a string like '1min' or as an integer.

        Returns:
            int: The calculated batch interval in minutes.

        Raises:
            ValueError: If batch_size is not a positive integer, or if granularity cannot be converted to an integer.
        """
        # Validate batch_size
        if not isinstance(batch_size, int) or batch_size <= 0:
            raise ValueError("Batch size must be a positive integer.")
        
        # Get granularity in minutes using helper method
        granularity_minutes = self.get_granularity_in_minutes(granularity)

        # Calculate batch interval in minutes
        batch_interval_minutes = batch_size * granularity_minutes

        return batch_interval_minutes
 
 
    def get_fetch_end_time(self, run_mode, end_time=None, granularity=settings.DEFAULT_GRANULARITY, window_size=settings.DEFAULT_WINDOW_SIZE) -> str:
        """
        Calculates the fetch end time based on the run mode, granularity, window size, and end_time.

        Args:
            run_mode (Enum): The run mode, which can be HISTORICAL, BATCH, or REALTIME.
            granularity (str): The granularity string, e.g., '1min'.
            window_size (int): The window size to multiply by.
            end_time (str): The end time in the format 'YYYY-MM-DDTHH:MM:SSZ'.

        Returns:
            str: The resulting fetch end time in the format 'YYYY-MM-DDTHH:MM:SSZ'.
        
        Raises:
            ValueError: If the granularity format is unsupported.
        """ 
        match run_mode:
            case settings.RUN_MODE.HISTORICAL:
                
                # Calculate the detector interval in minutes based on granularity and window size
                detector_interval = self.get_detector_interval(granularity, window_size)

                # Parse end_time to a datetime object using the specified date-time format
                end_time_dt = datetime.strptime(end_time, settings.DATE_TIME_FORMAT)

                # Add the detector interval (in minutes) to the end_time
                end_time_fetch = end_time_dt + timedelta(minutes=detector_interval)
                
                # Return the updated end_time in the original format
                return end_time_fetch.strftime(settings.DATE_TIME_FORMAT)
    
            case settings.RUN_MODE.BATCH:
                ## formula = current_time 
                # Get the current time in the specified timezone and format it
                current_time = datetime.now(settings.TIMEZONE).strftime(settings.DATE_TIME_FORMAT)
                
                # Return the current time as the fetch end time
                return current_time
                
            case settings.RUN_MODE.REALTIME:
                ## formula = current_time 
                # Get the current time in the specified timezone and format it
                current_time = datetime.now(settings.TIMEZONE).strftime(settings.DATE_TIME_FORMAT)
                
                # Return the current time as the fetch end time
                return current_time 
            
            case _:
                # Handle invalid run modes
                raise ValueError("Invalid run mode.") 
            
 
    


    def get_fetch_start_time(self, run_mode, end_time=None, batch_size=settings.DEFAULT_BATCH_SIZE, granularity=settings.DEFAULT_GRANULARITY) -> str:
        """
        Calculates the fetch start time based on the run mode, end time, batch size, and granularity.

        Args:
            run_mode (Enum): The detection run mode, which can be HISTORICAL, BATCH, or REALTIME.
            end_time (str, optional): The end time in the format 'YYYY-MM-DDTHH:MM:SSZ'.
            batch_size (int, optional): The size of each batch.
            granularity (str, optional): The granularity string, e.g., '1min'.

        Returns:
            str: The calculated fetch start time in the format 'YYYY-MM-DDTHH:MM:SSZ'.

        Raises:
            ValueError: If granularity format is unsupported or if invalid run mode is provided.
        """ 
        match run_mode: 
            case settings.RUN_MODE.HISTORICAL:
                ## formula >= current_time - detection_interval 
                fetch_start_time = date.today().strftime(settings.DATE_TIME_FORMAT)
                return fetch_start_time 
            
            case settings.RUN_MODE.BATCH:
                ## formula = end_time - batch_size * granularity 
                
                # Convert granularity in minutes 
                granularity_minutes = self.get_granularity_in_minutes(granularity) 
                
                # Parse the end_time string into a datetime object
                end_time_dt = datetime.strptime(end_time, settings.DATE_TIME_FORMAT)

                # Calculate the total interval in minutes
                total_interval_minutes = batch_size * granularity_minutes

                # Subtract the interval from the end time to get the fetch start time
                fetch_start_time_dt = end_time_dt - timedelta(minutes=total_interval_minutes)

                # Format the fetch start time back to string
                fetch_start_time = fetch_start_time_dt.strftime(settings.DATE_TIME_FORMAT)

                return fetch_start_time
 
            case settings.RUN_MODE.REALTIME:
                ## formula = end_time - granularity 
                
                # Convert granularity in minutes 
                granularity_minutes = self.get_granularity_in_minutes(granularity) 
                
                # Parse the end_time string into a datetime object
                end_time_dt = datetime.strptime(end_time, settings.DATE_TIME_FORMAT)
 
                # Calculate fetch start time by subtracting granularity from end_time
                fetch_start_time_dt = end_time_dt - timedelta(minutes=granularity_minutes)
                
                # Format the fetch start time back to string
                fetch_start_time = fetch_start_time_dt.strftime(settings.DATE_TIME_FORMAT)
                
                return fetch_start_time 
            
            case _:
                logging.error("Invalid run mode.") 
         

    def get_detector_interval(self, granularity=settings.DEFAULT_GRANULARITY, window_size=settings.DEFAULT_WINDOW_SIZE): 
        """
        Calculates the detector interval in minutes based on the granularity and window size.

        Args:
            granularity (str): The granularity string, e.g., '1min'.
            window_size (int): The window size to multiply by.

        Returns:
            detector_interval: The resulting detector_interval in minutes. 
        
        Raises:
            ValueError: If the granularity format is unsupported.
        """  
        granularity_minutes = self.get_granularity_in_minutes(granularity)
        # Multiply by the window size and convert to float to calculate the detector interval 
        detector_interval  = granularity_minutes * window_size 
        return detector_interval
 
 


    def get_granularity_in_minutes(self, granularity=settings.DEFAULT_GRANULARITY):
        """
        Convert granularity string to minutes.

        Args:
            granularity (str or int): The granularity factor, either as a string like '1min' or as an integer.

        Returns:
            int: The granularity converted to minutes.

        Raises:
            ValueError: If granularity format is not supported.
        """
        # If granularity is already an integer (representing minutes), return it directly
        if isinstance(granularity, int):
            return granularity

        # Convert granularity to lowercase for case insensitivity
        granularity = granularity.lower()

        # Parse the numeric part of the granularity string into minutes
        if granularity.endswith("min"):
            numeric_part = int(granularity[:-3])
            granularity_minutes = numeric_part
        elif granularity.endswith("hour"):
            numeric_part = int(granularity[:-4])
            granularity_minutes = numeric_part * 60
        elif granularity.endswith("day"):
            numeric_part = int(granularity[:-3])
            granularity_minutes = numeric_part * 1440
        elif granularity.endswith("s"):
            numeric_part = int(granularity[:-1])
            granularity_minutes = numeric_part / 60  # Convert seconds to minutes
        else:
            raise ValueError("Unsupported granularity format")

        return granularity_minutes
    

    def get_granularity_in_seconds(self, granularity=settings.DEFAULT_GRANULARITY):
        """
        Convert granularity string to seconds.

        Args:
            granularity (str or int): The granularity factor, either as a string like '1min' or as an integer.

        Returns:
            int: The granularity converted to seconds.

        Raises:
            ValueError: If granularity format is not supported.
        """
        # If granularity is in second returns it 
        if granularity.endswith("s"):
            numeric_part = int(granularity[:-1])
            return numeric_part
        else:
            return  self.get_granularity_in_minutes(granularity)*60
 
        
 
    def get_default_detector_name(self):
        """
        Returns a string representing a detector name in the format 'detector_<current timestamp>'.

        Returns:
            str: Detector name string.
        """
        current_timestamp = datetime.now(settings.TIMEZONE).strftime(settings.DATE_TIME_FORMAT)
        detector_name = f"detector_{current_timestamp}"
        return detector_name
    
    
    # GENERIC METHODS 
    
    # METHODS FOR HISTORICAL  DETECTION 
    
    # METHODS FOR BATCH DETECTION 
    
    # METHODS FOR REALTIME DETECTION 
