from opensearch_sdk_py.rest.extension_rest_request import ExtensionRestRequest
from opensearch_sdk_py.rest.extension_rest_response import ExtensionRestResponse 
from opensearch_sdk_py.rest.rest_status import RestStatus 

from siem_mtad_gat.data_ingestion.wazuh.wazuh_data_ingestor import WazuhDataIngestor
from siem_mtad_gat.data_transformer import DataTypeTransformer
from siem_mtad_gat.data_transformer import DataPreprocessor
from siem_mtad_gat.data_manager.data_storage_manager import DataStorageManager 
from siem_mtad_gat.data_manager.data_retrieval_manager import DataRetrievalManager 
from siem_mtad_gat.mtad_gat_pytorch.train_alab import train_MTAD_GAT
from datetime import datetime 
import siem_mtad_gat.settings as settings
import logging
import json 




class DetectorCreationHandler(): 
    def handle_create_detector_request(rest_request: ExtensionRestRequest) -> ExtensionRestResponse: 

        logging.info(f"Request body: {rest_request.content()}") 
        logging.info(f"Request headers: {rest_request.headers}")

        json_string = rest_request.content().decode('utf-8')

        try:
            json_request = json.loads(json_string)
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON: {e}")
            print(f"JSON string causing error:\n{json_string}") 
    
        data_storage_manager = DataStorageManager() 
        data_storage_manager.save_detector_input_parameters(json_request) 

        data_retrieval_manager = DataRetrievalManager(data_storage_manager.uuid) 
        
        # Check if all required keys exist in json_request
        if all(key in json_request for key in ["columns", "index_date", "aggregation", "train_config"]): 
            # Create an instance of WazuhDataIngestor 
            wazuh_data_ingestor = WazuhDataIngestor()
            
            # Should be defined in settings.py 
            
            # Retrieve the training data for the specified date and list of features 
            input_data, datasource_name = wazuh_data_ingestor.get_training_data(json_request.get("index_date"), settings.WAZUH_COLUMNS_PATH)
                    
            # Convert data types into proper format 
            input_data = DataTypeTransformer.transform_data_types(input_data, settings.WAZUH_COLUMNS_PATH) 
            
            # Preprocess the data 
            train_data, test_data, train_stamps, test_stamps = DataPreprocessor.preprocess(input_data, json_request, stateful=False)
            
            # Train a detector 
            train_response = train_MTAD_GAT(train_data, test_data, train_stamps, test_stamps, json_request.get("train_config"), test_labels=None) 

        else:
            # Raise an exception if one or more required keys are missing
            missing_keys = [key for key in ["columns", "index_date", "aggregation", "train_config"] if key not in json_request]
            raise ValueError(f"Missing required keys in json_request: {', '.join(missing_keys)}")
        

        updated_detector_input_parameters = {
             "detector_id" : data_storage_manager.uuid, 
             "created_time": datetime.now(settings.TIMEZONE).strftime(settings.DATE_TIME_FORMAT), 
             "last_updated_time": datetime.now(settings.TIMEZONE).strftime(settings.DATE_TIME_FORMAT),
             "model_info": { 
                   "datasource": datasource_name, 
                   "start_time": "",
                    "end_time": "", 
                    "status": "CREATED", 
                    "errors": [], 
                    #"diagnostics_info": {
                     #   "model_state": train_response 
        #}
             }}
        
        data_storage_manager.update_detector_input_parameters_after_training(updated_detector_input_parameters)

        # Initialize response object
        response = {
            "detector_id": updated_detector_input_parameters.get("detector_id", ""),
            "created_time": updated_detector_input_parameters.get("created_time", ""),
            "last_updated_time": updated_detector_input_parameters.get("last_updated_time", ""),
            "model_info": {
                "datasource": updated_detector_input_parameters["model_info"].get("datasource", ""),
                "start_time": updated_detector_input_parameters["model_info"].get("start_time", ""),
                "end_time": updated_detector_input_parameters["model_info"].get("end_time", ""),
                "display_name": json_request.get("display_name", ""),
                "train_config": json_request.get("train_config", {}),
                "aggregation_config": json_request.get("aggregation_config", {}),
                "status": updated_detector_input_parameters["model_info"].get("status", ""),
                "errors": updated_detector_input_parameters["model_info"].get("errors", []),
                "diagnostics_info": {
                    "model_state": train_response
                }
            }
        }  
                
        DataStorageManager.destroy_instance()
        DataRetrievalManager.destroy_instance() 
        
        logging.info(f"Response body: {response}")
        response_bytes = bytes(f"{json.dumps(response)}", "utf-8")
        
        return ExtensionRestResponse(rest_request, RestStatus.OK, response_bytes, ExtensionRestResponse.JSON_CONTENT_TYPE) 
    
