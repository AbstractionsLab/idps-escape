"""Settings for the SIEM-MTAD-GAT package"""
from enum import Enum
import logging
import os
from datetime import datetime, timezone
import time 

###Configuration files'  path

# Date and Time 
# Timezone
#TIMEZONE = time.strftime("%Z", time.localtime()) 
#TIMEZONE = time.tzname 
TIMEZONE = timezone.utc
# print(TIMEZONE) 

# Date and Time formats 
DATE_FORMAT = "%Y-%m-%d" 
DATE_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# Run Modes 
RUN_MODE = Enum('run_mode', ['HISTORICAL', 'BATCH', 'REALTIME'])
DEFAULT_RUN_MODE = "HISTORICAL"

# Default values 
DEFAULT_BATCH_SIZE = 10 
DEFAULT_WINDOW_SIZE = 10 
DEFAULT_GRANULARITY = "1min"
DEFAULT_REALTIME_INTERVAL = 1
MAX_FILE_SIZE = 500 * 1024 * 1024  


# MTAD-GAT 
#ROOT =  os.path.dirname(__file__)

ROOT = os.getcwd() 

SIEM_MTAD_GAT_FOLDER = os.path.join(ROOT, 'siem_mtad_gat') 

ASSETS_FOLDER = os.path.join(SIEM_MTAD_GAT_FOLDER, 'assets') 

DEFULAT_CONFIGS_FOLDER = os.path.join(ASSETS_FOLDER, os.path.join('default_configs')) 

MTAD_GAT_CONFIG_TRAINING_DEFAULT =  os.path.join(DEFULAT_CONFIGS_FOLDER, 'mtad_gat_train_config_default_args.json')

# Default detector input configuration
#DETECTOR_CONFIG_FOLDER = os.path.join(CONFIG_FOLDER, 'detectors')
DEFAULT_DETECTOR_INPUT_CONFIG = os.path.join(DEFULAT_CONFIGS_FOLDER, 'default_detector_input_config.json') 


# Used for logging 
LOGS_FOLDER = os.path.join(SIEM_MTAD_GAT_FOLDER, 'logs')
#EXPORT_FOLDER = os.getcwd()

OUTPUT_LOGS = os.path.join(LOGS_FOLDER, 'output_logs') 

# Detectors data storage path
DETECTOR_MODELS_STORAGE_FOLDER = os.path.join(ASSETS_FOLDER, 'detector_models') 

# Storage path for individual detector models, where {id} will be replaced by the detector ID
DETECTOR_FOLDER = os.path.join(DETECTOR_MODELS_STORAGE_FOLDER, '{id}') 
# Base path for storing training outputs
TRAINING_STORAGE_FOLDER = os.path.join(DETECTOR_FOLDER, 'training') 
# Base path for storing inputs
INPUT_STORAGE_FOLDER = os.path.join(DETECTOR_FOLDER, 'input') 
# Base path for storing prediction outputs
PREDICTION_STORAGE_FOLDER = os.path.join(DETECTOR_FOLDER, 'prediction') 
# Base path for storing SPOT outputs
SPOT_TRAIN_STORAGE_FOLDER = os.path.join(TRAINING_STORAGE_FOLDER, 'spot') 
SPOT_PREDICT_STORAGE_FOLDER = os.path.join(PREDICTION_STORAGE_FOLDER, 'uc-{use_case_no}_spot_{exec_timestamp}') 

# Training 
# Path to store the trained model file
MODEL_FILE_PATH = os.path.join(TRAINING_STORAGE_FOLDER, 'model.pt')  
# Path to store training output data in pickle format
TRAIN_OUTPUT_PKL_FILE_PATH = os.path.join(TRAINING_STORAGE_FOLDER, 'train_output.pkl')
# Path to store test output data in pickle format
TEST_OUTPUT_PKL_FILE_PATH = os.path.join(TRAINING_STORAGE_FOLDER, 'test_output.pkl')
# Path to store the training losses data
TRAINING_LOSSES_FILE_PATH = os.path.join(TRAINING_STORAGE_FOLDER, 'losses_train_data.json')
# Path to store the training losses data in png 
TRAINING_LOSSES_IMAGE_PATH = os.path.join(TRAINING_STORAGE_FOLDER, 'train_losses.png')
# Path to store the training losses data in png 
VALIDATION_LOSSES_IMAGE_PATH = os.path.join(TRAINING_STORAGE_FOLDER, 'validation_losses.png')
# Path to store spot output train data in json
SPOT_TRAIN_FILE_PATH = os.path.join(SPOT_TRAIN_STORAGE_FOLDER, 'spot_feature-{feature}.{ext}')
# Path to store the preprocessing scaler
SCALER_FILE_PATH = os.path.join(TRAINING_STORAGE_FOLDER, 'scaler.pkl')  

# Input 
# Path to the JSON file containing input parameters for the detector
DETECTOR_INPUT_PARAMETERS_FILE_PATH = os.path.join(INPUT_STORAGE_FOLDER, 'detector_input_parameters.json') 
# Path to store the training configuration file
TRAINING_CONFIG_FILE_PATH = os.path.join(INPUT_STORAGE_FOLDER, 'training_config.json')


# Prediction 
# Current timestamp in current date format 
# The datetime format defined for other values could not be used here since it had colons (:) in it which were not being parsed on windows 
CURRENT_TIMESTAMP = datetime.now(TIMEZONE).strftime("%Y-%m-%d_%H-%M-%S")

#CURRENT_TIMESTAMP = datetime.now(TIMEZONE).strftime(DATE_TIME_FORMAT)
#CURRENT_TIMESTAMP = datetime.now(TIMEZONE).strftime(DATE_FORMAT)
#uc-n_prediction_data-N_exec-timestamp.json 
#file_name = 'uc-{use_case_no}_prediction_data-{file_no}'
PREDICTED_DATA_FILE_PATH = os.path.join(PREDICTION_STORAGE_FOLDER, 'uc-{use_case_no}_predicted_data-{file_no}_{exec_timestamp}.json')  
PREDICTED_ANOMALIED_DATA_FILE_PATH = os.path.join(PREDICTION_STORAGE_FOLDER, 'uc-{use_case_no}_predicted_anomalies_data-{file_no}_{exec_timestamp}.json')  




# Base path for storing prediction outputs
# Define the path with the current timestamp appended
# PREDICTION_OUTPUT_STORAGE_PATH = os.path.join(DETECTOR_FOLDER, f'prediction_{current_timestamp}') 

# PREDICTION_OUTPUT_FILE_PATH = os.path.join(PREDICTION_OUTPUT_STORAGE_PATH, 'predict_output.json')



# Path to store the input data used for predictions
PREDICTION_INPUT_DATA_STORAGE_PATH = os.path.join(PREDICTION_STORAGE_FOLDER, 'input_data')
# Path to store input data in pickle format
PREDICTION_DATA_PKL_FILE_PATH = os.path.join(PREDICTION_INPUT_DATA_STORAGE_PATH, 'input_data.pkl')
# Path to store input data in CSV format
PREDICTION_DATA_CSV_FILE_PATH = os.path.join(PREDICTION_INPUT_DATA_STORAGE_PATH, 'input_data.csv')
# Path to store the summary of predictions
SUMMARY_FILE_PATH = os.path.join(PREDICTION_STORAGE_FOLDER, 'summary.txt')
# Path to store input data used for training
INPUT_DATA_STORAGE_PATH = os.path.join(INPUT_STORAGE_FOLDER, 'input_data')
# Path to store training input data in pickle format
INPUT_DATA_PKL_FILE_PATH = os.path.join(INPUT_DATA_STORAGE_PATH, 'input_data.pkl')
# Path to store training input data in CSV format
INPUT_DATA_CSV_FILE_PATH = os.path.join(INPUT_DATA_STORAGE_PATH, 'input_data.csv')
# Path to store the training logs file
TRAIN_LOGS_FILE_PATH = os.path.join(TRAINING_STORAGE_FOLDER, 'training_logs.txt')






# Wazuh Columns configuration
WAZUH_CONFIG_FOLDER = os.path.join(ASSETS_FOLDER, 'wazuh')
WAZUH_COLUMNS_PATH = os.path.join(WAZUH_CONFIG_FOLDER, 'wazuh_columns.json') 


# Secrets folder 
SECRETS_FOLDER = os.path.join(ASSETS_FOLDER, 'secrets')
WAZUH_CREDENTIALS_PATH = os.path.join(SECRETS_FOLDER, 'wazuh_credentials.json') 



# Default alert data file from Wazuh 
# For training 
TRAIN_DATA_FOLDER = os.path.join(ASSETS_FOLDER, os.path.join('data', 'train')) 
sample_train_file_name = 'sample-alerts-train-{year}-{month}.json'
DEFAULT_TRAIN_DATA = os.path.join(TRAIN_DATA_FOLDER, sample_train_file_name) 


# For prediction 
PREDICT_DATA_FOLDER = os.path.join(ASSETS_FOLDER, os.path.join('data', 'predict'))
sample_predict_file_name = 'sample-alerts-predict-{year}-{month}-{day}.json'
DEFAULT_PREDICT_DATA = os.path.join(PREDICT_DATA_FOLDER, sample_predict_file_name) 


# Drivers folder 
DRIVERS_FOLDER = os.path.join(ASSETS_FOLDER, 'drivers') 
# Driver files 
DRIVER_YAML_FILE = os.path.join(DRIVERS_FOLDER, '{name}.yaml')





#### Logging settings
SIMPLE_LOGGING_FORMAT = "%(message)s"
LEVELED_LOGGING_FORMAT = "%(levelname)s: %(message)s"
VERBOSE_LOGGING_FORMAT = "[%(levelname)-8s] %(message)s"
VERBOSE2_LOGGING_FORMAT = "[%(levelname)-8s] (%(name)s @%(lineno)4d) %(message)s"
TIMED_LOGGING_FORMAT = "%(asctime)s" + " " + VERBOSE2_LOGGING_FORMAT
QUIET_LOGGING_LEVEL = logging.WARNING
VERBOSE_LOGGING_LEVEL = logging.INFO
VERBOSE2_LOGGING_LEVEL = logging.DEBUG
VERBOSE3_LOGGING_LEVEL = logging.DEBUG - 1

##Default:
DEFAULT_LOGGING_LEVEL = QUIET_LOGGING_LEVEL
DEFAULT_LOGGING_FORMAT = TIMED_LOGGING_FORMAT


# File names 
LOGGING_FILE_NAME = os.path.join(OUTPUT_LOGS, '{name}.log') 
