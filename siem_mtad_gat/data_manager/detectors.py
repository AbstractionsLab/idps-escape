import json 
import os 
from typing import List 
from datetime import datetime
import siem_mtad_gat.settings as settings

DATA_STORAGE_BASE_PATH = settings.DETECTOR_MODELS_STORAGE_FOLDER 
DETECTOR_INPUT_PARAMETERS_FILE_PATH = 'input/detector_input_parameters.json'

# Check if the folder exists, and if not, create it
if not os.path.exists(DATA_STORAGE_BASE_PATH):
    os.makedirs(DATA_STORAGE_BASE_PATH) 

# TO-REDESIGN (move all file system manipulations to a dedicated file management module and refactor all code base accordingly)

def retrieve_all_detector_parameters():
    """
    Retrieve and combine data from all detector input parameter files.

    :return: Combined JSON object containing data from all detector input parameter files.
    """
    combined_data = []
    for folder_name in os.listdir(DATA_STORAGE_BASE_PATH):
        folder_path = os.path.join(DATA_STORAGE_BASE_PATH, folder_name)
        if os.path.isdir(folder_path):
            param_file_path = os.path.join(folder_path, DETECTOR_INPUT_PARAMETERS_FILE_PATH)
            if os.path.exists(param_file_path):
                with open(param_file_path, 'r') as f:
                    detector_params = json.load(f) 
                    # Add condition to check if the detector was  trained successfully 
                    model_info = detector_params.get("model_info", {})
                    if model_info.get("status") == "CREATED":   
                        combined_data.append(detector_params)
        
    combined_data = json.dumps(combined_data)
    return combined_data 




def retrieve_all_detector_parameters_sorted():
    """
    Retrieve and combine data from all detector input parameter files, sorted by created_time.

    :param data_storage_base_path: The base path where detector parameter files are stored.
    :return: Combined JSON object containing data from all detector input parameter files, sorted by created_time.
    """
    combined_data = []
    for folder_name in os.listdir(DATA_STORAGE_BASE_PATH):
        folder_path = os.path.join(DATA_STORAGE_BASE_PATH, folder_name)
        if os.path.isdir(folder_path):
            param_file_path = os.path.join(folder_path, DETECTOR_INPUT_PARAMETERS_FILE_PATH)
            if os.path.exists(param_file_path):
                with open(param_file_path, 'r') as f:
                    detector_params = json.load(f) 
                     # Check if the model status is "CREATED"
                    model_info = detector_params.get("model_info", {})
                    if model_info.get("status") == "CREATED":                         
                        created_time_str = detector_params.get("created_time")
                        if created_time_str:
                            created_time = datetime.strptime(created_time_str, settings.DATE_TIME_FORMAT)
                            detector_params["created_time"] = created_time  # Store datetime object for sorting
                            combined_data.append(detector_params)
    
    # Sort the list of dictionaries based on the created_time in descending order
    combined_data.sort(key=lambda x: x["created_time"])
    
    # Convert datetime objects back to strings for the final JSON output
    for detector_params in combined_data:
        detector_params["created_time"] = detector_params["created_time"].strftime(settings.DATE_TIME_FORMAT)
    
    combined_data_json = json.dumps(combined_data)
    return combined_data_json 



def retrieve_all_detector_ids() -> List[str]:
    """
    Retrieves detector ids from the input parameter files.

    :return:
        List[str]: A list representing the stack of detector ids.
    """
    detectors = []
    for folder_name in os.listdir(DATA_STORAGE_BASE_PATH):
        folder_path = os.path.join(DATA_STORAGE_BASE_PATH, folder_name)
        if os.path.isdir(folder_path):
            param_file_path = os.path.join(folder_path, DETECTOR_INPUT_PARAMETERS_FILE_PATH)
            if os.path.exists(param_file_path):
                with open(param_file_path, 'r') as f:
                    detector_id = json.load(f).get("detector_id") 
                    if detector_id != None: 
                        detectors.append(detector_id)
        
    return detectors  




def retrieve_all_detector_ids_sorted() -> List[str]:
    """
    Retrieves and sorts detector ids from the input parameter files based on the created_time timestamp.

    :param data_storage_base_path: The base path where the detector parameter files are stored.
    :return:
        List[str]: A list representing the sorted stack of detector ids.
    """
    detectors = []
    for folder_name in os.listdir(DATA_STORAGE_BASE_PATH):
        folder_path = os.path.join(DATA_STORAGE_BASE_PATH, folder_name)
        if os.path.isdir(folder_path):
            param_file_path = os.path.join(folder_path, DETECTOR_INPUT_PARAMETERS_FILE_PATH)
            if os.path.exists(param_file_path):
                with open(param_file_path, 'r') as f:
                    data = json.load(f)
                    detector_id = data.get("detector_id")
                    created_time_str = data.get("created_time")
                    if detector_id is not None and created_time_str is not None:
                        created_time = datetime.strptime(created_time_str, settings.DATE_TIME_FORMAT)
                        detectors.append((detector_id, created_time))
    
    # Sort the list of tuples based on the created_time
    detectors.sort(key=lambda x: x[1])
    
    # Extract the sorted detector ids
    sorted_detector_ids = [detector_id for detector_id, _ in detectors]
    
    return sorted_detector_ids 



def retrieve_all_detector_ids_and_names() -> List[dict]:
    """
    Retrieves detector IDs and display names from the input parameter files.

    :param data_storage_base_path: The base path where detector parameter files are stored.
    :return:
        List[dict]: A list of dictionaries containing detector IDs and display names.
                    Each dictionary has keys 'detector_id' and 'display_name'.
    """
    detectors = []
    for folder_name in os.listdir(DATA_STORAGE_BASE_PATH):
        folder_path = os.path.join(DATA_STORAGE_BASE_PATH, folder_name)
        if os.path.isdir(folder_path):
            param_file_path = os.path.join(folder_path, DETECTOR_INPUT_PARAMETERS_FILE_PATH)
            if os.path.exists(param_file_path):
                with open(param_file_path, 'r') as f:
                    param_data = json.load(f)
                    detector_id = param_data.get("detector_id")
                    display_name = param_data.get("display_name")
                    if detector_id is not None:
                        detectors.append({
                            "detector_id": detector_id,
                            "display_name": display_name
                        })
        
    return detectors 


def retrieve_all_detectors_info_sorted() -> List[dict]:
    """
    Retrieves and sorts detector IDs and display names from the input parameter files based on the created_time timestamp.

    :param data_storage_base_path: The base path where detector parameter files are stored.
    :return:
        List[dict]: A list of dictionaries containing detector IDs and display names,
                    sorted by the created_time timestamp.
                    Each dictionary has keys 'detector_id' and 'display_name'.
    """
    detectors = []
    for folder_name in os.listdir(DATA_STORAGE_BASE_PATH):
        folder_path = os.path.join(DATA_STORAGE_BASE_PATH, folder_name)
        if os.path.isdir(folder_path):
            param_file_path = os.path.join(folder_path, DETECTOR_INPUT_PARAMETERS_FILE_PATH)
            if os.path.exists(param_file_path):
                with open(param_file_path, 'r') as f:
                    param_data = json.load(f)
                    detector_id = param_data.get("detector_id")
                    display_name = param_data.get("display_name")
                    created_time_str = param_data.get("created_time") 
                    model_info = param_data.get("model_info") 
                    if model_info is not None: 
                        data_source = model_info.get("datasource")
                    # Filter out None values and ensure all items are strings
                    columns_list = param_data.get("columns") 
                    if columns_list is not None: 
                        filtered_columns = [str(col) for col in columns_list if col is not None]
                        columns = ", ".join(filtered_columns)  
                    if detector_id is not None and created_time_str is not None and display_name is not None and columns is not None and data_source is not None:
                        created_time = datetime.strptime(created_time_str, settings.DATE_TIME_FORMAT)
                        detectors.append({
                            "detector_id": detector_id,
                            "display_name": display_name,
                            "created_time": created_time, 
                            "description" : "The detector was trained using data from " + data_source + " , including the features: " + columns + "."
                        })
    
    # Sort the list of dictionaries based on the created_time
    detectors.sort(key=lambda x: x["created_time"])
    
    # for detector_params in detectors:
    #     detector_params["created_time"] = detector_params["created_time"].strftime(settings.DATE_TIME_FORMAT) 
        
    # Remove the 'created_time' key from the dictionaries after sorting
    for detector in detectors:
        detector.pop("created_time")
    
    return detectors
 
 