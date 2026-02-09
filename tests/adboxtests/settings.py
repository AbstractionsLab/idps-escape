
from datetime import datetime, timezone
import os

TIMEZONE = timezone.utc

#root folders
ROOT = os.getcwd()
adbox_FOLDER = os.path.join(ROOT, 'adbox')
TESTS = os.path.join(ROOT, 'tests')  
ASSETS_FOLDER_CONFIGS = os.path.join(adbox_FOLDER, 'assets')
ASSETS_FOLDER_DETECTORS = os.path.join(TESTS, 'assets')
ASSETS_FOLDER_DRIVERS =os.path.join(TESTS, 'assets')
EMPTY=os.path.join(ASSETS_FOLDER_DETECTORS, 'empty_folder')

#default configurations 
DEFAULT_CONFIGS_FOLDER = os.path.join(ASSETS_FOLDER_CONFIGS, os.path.join('default_configs')) 
MTAD_GAT_CONFIG_TRAINING_DEFAULT =  os.path.join(DEFAULT_CONFIGS_FOLDER, 'mtad_gat_train_config_default_args.json')
DEFAULT_DETECTOR_INPUT_CONFIG = os.path.join(DEFAULT_CONFIGS_FOLDER, 'default_detector_input_config.json') # Default detector input configuration


# Used for logging 
LOGS_FOLDER = os.path.join(TESTS, 'logs')
OUTPUT_LOGS = os.path.join(LOGS_FOLDER, 'output_logs') 

# Detectors data storage path
DETECTOR_MODELS_STORAGE_FOLDER = os.path.join(ASSETS_FOLDER_DETECTORS, 'detector_models') 

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

#prediction
PREDICTED_DATA_FILE_PATH = os.path.join(PREDICTION_STORAGE_FOLDER, 'uc-{use_case_no}_predicted_data-{file_no}_{exec_timestamp}.json')  
PREDICTED_ANOMALIES_DATA_FILE_PATH = os.path.join(PREDICTION_STORAGE_FOLDER, 'uc-{use_case_no}_predicted_anomalies_data-{file_no}_{exec_timestamp}.json')  


# Prediction
# Current timestamp in current date format 
# The datetime format defined for other values could not be used here since it had colons (:) in it which were not being parsed on windows 
CURRENT_TIMESTAMP = datetime.now(TIMEZONE).strftime("%Y-%m-%d_%H-%M-%S")

#CURRENT_TIMESTAMP = datetime.now(TIMEZONE).strftime(DATE_TIME_FORMAT)
#CURRENT_TIMESTAMP = datetime.now(TIMEZONE).strftime(DATE_FORMAT)


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

# Drivers folder 
DRIVERS_FOLDER = os.path.join(ASSETS_FOLDER_DRIVERS, 'drivers') 
# Driver files 
DRIVER_YAML_FILE = os.path.join(DRIVERS_FOLDER, '{name}.yaml')
