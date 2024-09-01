import os
import json,pickle
import uuid
import threading
import numpy as np
import torch 
import matplotlib.pyplot as plt
import siem_mtad_gat.settings as settings
import re
import yaml
import logging 

os.makedirs(settings.OUTPUT_LOGS, exist_ok=True)
logging.basicConfig(filename=settings.LOGGING_FILE_NAME.format(name=__name__), format=settings.DEFAULT_LOGGING_FORMAT) 
logger = logging.getLogger(__name__)
logger.setLevel(settings.DEFAULT_LOGGING_LEVEL) 

# TO-REDESIGN (move all file system manipulations to a dedicated file management module and refactor all code base accordingly)

class DataStorageManager:
    """
    DataStorageManager class to handle creation of folders, JSON files and model training outputs for detectors 
    with proper concurrency control and singleton design pattern.
    """
    
    # Semaphore to prevent concurrent access to the sensitive resource
    _semaphore = threading.Semaphore()

    # Singleton instance
    _instance = None

    def __new__(cls, *args, **kwargs):
        """
        Ensure only one instance of DataStorageManager exists (Singleton Pattern).
        """ 
        if cls._instance is None: 
            if args:  
                cls._instance = super(DataStorageManager, cls).__new__(cls) 
                cls._instance._initialize(args[0]) 
            else:             
                cls._instance = super(DataStorageManager, cls).__new__(cls) 
                cls._instance._initialize()
        return cls._instance 
    

    def _initialize(self, detector_id: str = None): 
        """
        Initialize the DataStorageManager instance with a unique UUID and path.
        """          
        if detector_id == None: 
            self.base_path = settings.DETECTOR_MODELS_STORAGE_FOLDER 
            # Check if the folder exists, and if not, create it
            if not os.path.exists(self.base_path):
                os.makedirs(self.base_path)  
                
            # Set uuid     
            self.uuid = str(uuid.uuid4())
            self.path = settings.DETECTOR_FOLDER.format(id=self.uuid)
            os.makedirs(self.path, exist_ok=True) 
        
        else: 
            self.base_path = settings.DETECTOR_MODELS_STORAGE_FOLDER 
            # Check if the folder exists, and if not, create it
            if not os.path.exists(self.base_path):
                os.makedirs(self.base_path)  
                
            # Set uuid 
            self.uuid = detector_id 
            self.path = settings.DETECTOR_FOLDER.format(id=self.uuid) 
 

    def save_detector_input_parameters(self, save_detector_input_parameters):
        """
        Store the given JSON object in a file named 'detector_input_parameters.json' in the UUID folder.

        :param json_obj: The JSON object to be stored in the 'detector_input_parameters.json' file.
        :type json_obj: dict
        :return: The UUID of the folder.
        :rtype: str
        """
        with self._semaphore: 
            input_storage_folder = settings.INPUT_STORAGE_FOLDER.format(id=self.uuid)
            # Check if the folder exists, and if not, create it
            if not os.path.exists(input_storage_folder):
                os.makedirs(input_storage_folder)  
            
            # Define the path to the JSON file
            detector_input_parameters_file_path = settings.DETECTOR_INPUT_PARAMETERS_FILE_PATH.format(id=self.uuid)

            
            # Write the JSON object to the file
            with open(detector_input_parameters_file_path, 'w') as json_file:
                json.dump(save_detector_input_parameters, json_file, indent=4)
            
            print(f"JSON file 'detector_input_parameters.json' saved at {detector_input_parameters_file_path}.")


    def update_detector_input_parameters_after_training(self, updated_detector_input_parameters):
        """
        Update the 'detector_input_parameters.json' file with the given JSON object.

        :param update_json_obj: The JSON object containing the updates to be applied to the 'detector_input_parameters.json' file.
        :type update_json_obj: dict
        """
        with self._semaphore:
            # Define the path to the JSON file
            detector_input_parameters_file_path = settings.DETECTOR_INPUT_PARAMETERS_FILE_PATH.format(id=self.uuid) 
            
            # Read the existing JSON file
            if os.path.exists(detector_input_parameters_file_path):
                with open(detector_input_parameters_file_path, 'r') as json_file:
                    existing_params = json.load(json_file)
            else:
                existing_params = {}
            
            updated_detector_params = {
            **existing_params,  # Use unpacking to include all keys from json_request 
            **updated_detector_input_parameters 
            }
            
            
            # Write the updated JSON object to the file
            with open(detector_input_parameters_file_path, 'w') as json_file:
                json.dump(updated_detector_params, json_file, indent=4)
            
            print(f"JSON file 'detector_input_parameters.json' updated after training at {detector_input_parameters_file_path}.")


    def save_input_data(self, input_data, save_pickle=False, save_csv=False, caller:str=None):
        """
        Save input data in specified formats (pickle and/or CSV) within the UUID folder.

        :param input_data: The data to be saved, expected to be a pandas DataFrame.
        :param save_pickle: Boolean indicating whether to save the data as a pickle file.
        :param save_csv: Boolean indicating whether to save the data as a CSV file.
        """
        with self._semaphore: 
            if caller == "train": 
                input_storage_folder = settings.INPUT_STORAGE_FOLDER.format(id=self.uuid)
                # Check if the folder exists, and if not, create it
                if not os.path.exists(input_storage_folder):
                    os.makedirs(input_storage_folder)    
                 
                input_data_dir = settings.INPUT_DATA_STORAGE_PATH.format(id=self.uuid) 
                os.makedirs(input_data_dir, exist_ok=True) 
            
                if save_pickle:
                    # Define the pickle file path
                    pickle_file_path = settings.INPUT_DATA_PKL_FILE_PATH.format(id=self.uuid) 

                    # Save the DataFrame as a pickle file
                    input_data.to_pickle(pickle_file_path)
                    print(f"Pickle file 'input_data.pkl' saved at {pickle_file_path}.")

                if save_csv:
                    # Define the CSV file path
                    csv_file_path =  settings.INPUT_DATA_CSV_FILE_PATH.format(id=self.uuid) 
                    # Save the DataFrame as a CSV file
                    input_data.to_csv(csv_file_path)
                    print(f"CSV file 'input_data.csv' saved at {csv_file_path}")
                
            
            elif caller == "predict": 
                prediction_output_dir = settings.PREDICTION_STORAGE_FOLDER.format(id=self.uuid) 
                os.makedirs(prediction_output_dir, exist_ok=True)  
            
                input_data_dir = settings.PREDICTION_INPUT_DATA_STORAGE_PATH.format(id=self.uuid) 
                os.makedirs(input_data_dir, exist_ok=True) 
            
                if save_pickle:
                    # Define the pickle file path
                    pickle_file_path = settings.PREDICTION_DATA_PKL_FILE_PATH.format(id=self.uuid) 

                    # Save the DataFrame as a pickle file
                    input_data.to_pickle(pickle_file_path)
                    print(f"Pickle file 'input_data.pkl' saved at {pickle_file_path}.")

                if save_csv:
                    # Define the CSV file path
                    csv_file_path =  settings.PREDICTION_DATA_CSV_FILE_PATH.format(id=self.uuid) 
                    # Save the DataFrame as a CSV file
                    input_data.to_csv(csv_file_path)
                    print(f"CSV file 'input_data.csv' saved at {csv_file_path}")
            else: 
                return 
            
    
    def save_predict_output(self, output, use_case_no, exec_timestamp, output_type): 
        with self._semaphore:
            prediction_output_dir = settings.PREDICTION_STORAGE_FOLDER.format(id=self.uuid)
            os.makedirs(prediction_output_dir, exist_ok=True) 

            # Define the regex pattern to match the file names 
            if output_type == "predicted_anomalies_data": 
                file_pattern = re.compile(rf"uc-{use_case_no}_predicted_anomalies_data-(\d+)_{exec_timestamp}\.json") 
                file_pattern_for_all_files = re.compile(rf"uc-{use_case_no}_predicted_anomalies_data-(\d+)_([^_]+)\.json") 
                
            else: 
                file_pattern = re.compile(rf"uc-{use_case_no}_predicted_data-(\d+)_{exec_timestamp}\.json") 
                file_pattern_for_all_files = re.compile(rf"uc-{use_case_no}_predicted_data-(\d+)_([^_]+)\.json") 
            
            
            file_no = 0  # Initialize file_no to 0 before the loop

            for filename in os.listdir(prediction_output_dir):  
                file_no = 0
                match = file_pattern.search(filename)
                match_all_files = file_pattern_for_all_files.search(filename) 
                                
                if match: 
                    file_no = max(file_no, int(match.group(1)))
                    break
                elif match_all_files: 
                    file_no = max(file_no, int(match_all_files.group(1))) + 1
                    break
                else: 
                    file_no = 1
                    
            
            if file_no == 0:  # If no matches were found, set file_no to 1
                file_no = 1
            
            if output_type == "predicted_anomalies_data": 
                predict_output_file_path = settings.PREDICTED_ANOMALIED_DATA_FILE_PATH.format(id=self.uuid, use_case_no=use_case_no, file_no=file_no, exec_timestamp=exec_timestamp)
            else: 
                predict_output_file_path = settings.PREDICTED_DATA_FILE_PATH.format(id=self.uuid, use_case_no=use_case_no, file_no=file_no, exec_timestamp=exec_timestamp)


            # Read existing data
            if os.path.exists(predict_output_file_path):
                with open(predict_output_file_path, 'r') as json_file:
                    try:
                        existing_data = json.load(json_file)
                    except json.JSONDecodeError:
                        existing_data = []  # Start with an empty list if the file is empty or contains invalid JSON
            else:
                existing_data = []

            # Ensure the output is a list
            if not isinstance(output, list):
                output = [output]

            # Append new data
            existing_data.extend(output)

            # Serialize data to check size
            serialized_data = json.dumps(existing_data, ensure_ascii=False, indent=4) 
            #print(len(serialized_data.encode('utf-8')))
            if len(serialized_data.encode('utf-8')) > settings.MAX_FILE_SIZE:
            # If the size exceeds max_file_size, create a new file with just the new data
                file_no += 1 
                if output_type == "predicted_anomalies_data":  
                    predict_output_file_path = settings.PREDICTED_ANOMALIED_DATA_FILE_PATH.format(id=self.uuid, use_case_no=use_case_no, file_no=file_no)
                else: 
                    predict_output_file_path = settings.PREDICTED_DATA_FILE_PATH.format(id=self.uuid, use_case_no=use_case_no, file_no=file_no)

                json.dump(output, json_file, indent=4) 
            else:
                # Write all the data back to the current file
                with open(predict_output_file_path, 'w') as json_file:
                    json.dump(existing_data, json_file, indent=4) 
                        
            
            print(f"JSON output appended at {predict_output_file_path}")
                    
                
    def save_train_logs(self, logs):
        """
        Save training logs to a subfolder named 'train_logs' within the detector path.

        :param logs: The training logs to be saved.
        """
        with self._semaphore: 
            training_storage_folder = settings.TRAINING_STORAGE_FOLDER.format(id=self.uuid)
            # Check if the folder exists, and if not, create it
            if not os.path.exists(training_storage_folder):
                os.makedirs(training_storage_folder)  
            
            log_file_path = settings.TRAIN_LOGS_FILE_PATH.format(id=self.uuid) 
            
            # Write the logs to a file
            with open(log_file_path, 'w') as log_file:
                log_file.write(logs)
            
            print(f"Training logs saved at {log_file_path}.")


    def save_model(self, model):
        """
        Save the model parameters to a file within the UUID folder.
        :param model: The model whose parameters are to be saved.
        """
        with self._semaphore: 
            training_storage_folder = settings.TRAINING_STORAGE_FOLDER.format(id=self.uuid)
            # Check if the folder exists, and if not, create it
            if not os.path.exists(training_storage_folder):
                os.makedirs(training_storage_folder)   
                
            model_path = settings.MODEL_FILE_PATH.format(id=self.uuid) 
            torch.save(model.state_dict(), model_path)
            print(f"Model parameters saved at {model_path}.")
        
        
    def save_summary(self, summary):
        """
        Save the summary dictionary as a JSON file.

        :param summary: Dictionary containing summary information.
        """ 
        with self._semaphore: 
            prediction_output_dir = settings.PREDICTION_STORAGE_FOLDER.format(id=self.uuid) 
            os.makedirs(prediction_output_dir, exist_ok=True) 
            
            summary_path = settings.SUMMARY_FILE_PATH.format(id=self.uuid) 
            with open(summary_path, "w") as f:
                json.dump(summary, f, indent=2)
            
            print(f"Summary saved at {summary_path}")


    def save_training_outputs(self, train_pred_df, test_pred_df): 
        """
        Save the training and test predictions as pickle files.

        :param train_pred_df: DataFrame containing training predictions.
        :param test_pred_df: DataFrame containing test predictions.
        """
        with self._semaphore:  
            training_storage_folder = settings.TRAINING_STORAGE_FOLDER.format(id=self.uuid)
            # Check if the folder exists, and if not, create it
            if not os.path.exists(training_storage_folder):
                os.makedirs(training_storage_folder)   
                
            
            train_output_file_path = settings.TRAIN_OUTPUT_PKL_FILE_PATH.format(id=self.uuid) 
            print(f"Saving output to {train_output_file_path}")
            train_pred_df.to_pickle(train_output_file_path)

            test_output_file_path = settings.TEST_OUTPUT_PKL_FILE_PATH.format(id=self.uuid) 

            print(f"Saving output to {test_output_file_path}")
            test_pred_df.to_pickle(test_output_file_path)

            print("Training and test outputs saved successfully.")
        
            
            
    def save_training_config(self, training_config):
        """
        Save the training config dictionary as a JSON file.

        :param training_config: Dictionary containing training config information.
        """ 
        with self._semaphore: 
            input_storage_folder = settings.INPUT_STORAGE_FOLDER.format(id=self.uuid)
            # Check if the folder exists, and if not, create it
            if not os.path.exists(input_storage_folder):
                os.makedirs(input_storage_folder)   
                
            training_config_path = settings.TRAINING_CONFIG_FILE_PATH.format(id=self.uuid) 
            with open(training_config_path, "w") as f:
                json.dump(training_config, f, indent=2)
            
            print(f"Training config saved at {training_config_path}. ")


    def save_losses(self, losses, plot : bool = True):
        """
        :param losses: dict with losses
        """

        with self._semaphore: 
            training_storage_folder = settings.TRAINING_STORAGE_FOLDER.format(id=self.uuid)
            # Check if the folder exists, and if not, create it
            if not os.path.exists(training_storage_folder):
                os.makedirs(training_storage_folder)  
                
            # Define the pickle file path
            file_path = settings.TRAINING_LOSSES_FILE_PATH.format(id=self.uuid) 
            # Save the json 
            with open(file_path, "w") as f:
                json.dump(losses, f, indent=2)
            print(f"Pickle file 'losses_train_data.json' saved at {file_path}.")

        if plot:
            plt.plot(losses.get("train_forecast"), label="Forecast loss")
            plt.plot(losses.get("train_recon"), label="Recon loss")
            plt.plot(losses.get("train_total"), label="Total loss")
            plt.title("Training losses during training")
            plt.xlabel("Epoch")
            plt.ylabel("RMSE")
            plt.legend() 
            train_loss_image_path = settings.TRAINING_LOSSES_IMAGE_PATH.format(id=self.uuid)  
            plt.savefig(train_loss_image_path, bbox_inches="tight")
            plt.close()

            plt.plot(losses.get("val_forecast"), label="Forecast loss")
            plt.plot(losses.get("val_recon"), label="Recon loss")
            plt.plot(losses.get("val_total"), label="Total loss")
            plt.title("Validation losses during training")
            plt.xlabel("Epoch")
            plt.ylabel("RMSE")
            plt.legend()
            validation_loss_image_path = settings.VALIDATION_LOSSES_IMAGE_PATH.format(id=self.uuid)   
            plt.savefig(validation_loss_image_path, bbox_inches="tight")
            plt.close()
      
   
   
    def save_yaml_predict(self, run_mode, index_date, detector_id, start_time, end_time, batch_size):
        """
        Creates a new YAML file with incremented number based on the existing files in the given folder.
        
        Parameters:
        - run_mode (str): Value for the 'run_mode' field in the YAML file.
        - index_date (str): Value for the 'index_date' field in the YAML file.
        - detector_id (str): Value for the 'detector_id' field in the YAML file.
        - start_time (str): Value for the 'start_time' field in the YAML file.
        - end_time (str): Value for the 'end_time' field in the YAML file.
        - batch_size (int): Value for the 'batch_size' field in the YAML file.

        Returns:
        - int: The number of the newly created file.
        """
        
        # List all files in the folder
        files = os.listdir(settings.DRIVERS_FOLDER)
        
        # Filter out YAML files and extract the numbers from their names
        numbers = []
        for file in files:
            if file.endswith('.yaml'):
                base_name = file.split('.')[0]  # e.g., 'uc_5'
                if base_name.startswith('uc_'):
                    try:
                        number = int(base_name.split('_')[1])
                        numbers.append(number)
                    except ValueError:
                        pass  # Skip files that don't have a valid number
        
        # Determine the next number
        next_number = max(numbers, default=0) + 1
        
        # Define the new filename
        new_filename = f"uc_{next_number}"
        new_file_path = settings.DRIVER_YAML_FILE.format(name=new_filename) 
        
        # Define the content for the new YAML file
        content = {
            'prediction': {
                'run_mode': run_mode,
                'index_date': index_date,
                'detector_id': detector_id,
                'start_time': start_time,
                'end_time': end_time,
                'batch_size': batch_size
            }
        }
        
        # Write the content to the new YAML file
        with open(new_file_path, 'w') as file:
            yaml.dump(content, file)
        
        print(f"yaml file {new_filename} stored at {new_file_path} ")

        # Return the new number
        return next_number 

            
    
    
    def save_yaml_train(self, training_request):
        """
        Creates a new YAML file with incremented number based on the existing files in the given folder.
        
        Parameters:
        - run_mode (str): Value for the 'run_mode' field in the YAML file.


        Returns:
        - int: The number of the newly created file.
        """
        
        # List all files in the folder
        files = os.listdir(settings.DRIVERS_FOLDER)
        
        # Filter out YAML files and extract the numbers from their names
        numbers = []
        for file in files:
            if file.endswith('.yaml'):
                base_name = file.split('.')[0]  # e.g., 'uc_5'
                if base_name.startswith('uc_'):
                    try:
                        number = int(base_name.split('_')[1])
                        numbers.append(number)
                    except ValueError:
                        pass  # Skip files that don't have a valid number
        
        # Determine the next number
        next_number = max(numbers, default=0) + 1
        
        # Define the new filename
        new_filename = f"uc_{next_number}"
        new_file_path = settings.DRIVER_YAML_FILE.format(name=new_filename) 
        
        # Define the content for the new YAML file
        content = {
            "training": training_request 
        }
        
        # Write the content to the new YAML file
        with open(new_file_path, 'w') as file:
            yaml.dump(content, file)
        
        print(f"yaml file {new_filename} stored at {new_file_path} ")
        # Return the new number
        return next_number  
    

    def save_spot_train(self, spot, feature:int=-1,file_ext="pkl"):
        """
       Save the dictionary of Argument of a spot object
        
        Parameters:
        - spot (SPOT): Instance of SPOT

        """
        with self._semaphore: 
            spot_storage_folder = settings.SPOT_TRAIN_STORAGE_FOLDER.format(id=self.uuid)
            # Check if the folder exists, and if not, create it
            if not os.path.exists(spot_storage_folder):
                os.makedirs(spot_storage_folder)   
            
            if feature==-1: feature='global'
            
            if file_ext=="pkl":
                    #save full spot object as pickle file
                    spot_path = settings.SPOT_TRAIN_FILE_PATH.format(id=self.uuid,feature=feature,ext=file_ext)
                    with open(spot_path , 'wb') as file: 
                        pickle.dump(spot, file=file) 
                    with open(spot_path, "rb") as f:
                        spot=pickle.load(f)

            elif file_ext=="json":
                di=spot.__dict__
                for k in di: 
                    v=di[k]
                    if isinstance(v, np.ndarray): di[k]=list(map(lambda x: float(x),v)) 
                    elif isinstance(v, np.float32): di[k]=float(v)

                spot_path = settings.SPOT_TRAIN_FILE_PATH.format(id=self.uuid,feature=feature,ext="json") 
                with open(spot_path, "w") as f:
                    json.dump(di, f)
            else:
                logging.exception(f"Invalide file extension for spot object")
            
            print(f"Spot object saved at {spot_path}.")

    def save_preprocessing_scaler(self,scaler):
        """
         
            
            Parameters:
            -  :  
        """
        with self._semaphore: 

            training_storage_folder = settings.TRAINING_STORAGE_FOLDER.format(id=self.uuid)
            # Check if the folder exists, and if not, create it
            if not os.path.exists(training_storage_folder):
                os.makedirs(training_storage_folder)  

            scaler_path = settings.SCALER_FILE_PATH.format(id=self.uuid)
            with open(scaler_path , 'wb') as file: 
                pickle.dump(scaler, file=file)
            print(f"Scaler for preprocessing  saved at {scaler_path}.")
    
    @classmethod
    def destroy_instance(cls):
        cls._instance = None

        
        
           
        

