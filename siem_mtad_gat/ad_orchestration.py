from opensearch_sdk_py import *   
from siem_mtad_gat.data_ingestion.wazuh.wazuh_data_ingestor import WazuhDataIngestor
from siem_mtad_gat.data_transformer import DataTypeTransformer
from siem_mtad_gat.data_transformer import DataPreprocessor
from siem_mtad_gat.data_manager.data_storage_manager import DataStorageManager 
from siem_mtad_gat.data_manager.data_retrieval_manager import DataRetrievalManager 
from siem_mtad_gat.data_manager.detectors import retrieve_all_detector_parameters 
from siem_mtad_gat.mtad_gat_pytorch.train_alab import train_MTAD_GAT
from siem_mtad_gat.mtad_gat_pytorch.predict_alab import predict_MTAD_GAT
from datetime import datetime 
import siem_mtad_gat.settings as settings


class ADOrchestration:
    """
    Class to handle the orchestration of anomaly detection training data.
    """

    def main(self): 
        """
        Main method of the orchestration class. 
        """ 
        
        # Define sample training request JSON object 
        json_training_request = {
                "index_date": "2024-*-*", 
                "categorical_features" : False, 
                "columns": [
                    "data.cpu_usage_%", 
                    "data.memory_usage_%" 
                ], 
                "aggregation": True,
                "aggregation_config": {
                    "fill_na_method": "Zero",
                    "padding_value": 0,
                    "granularity": "1min", 
                    "features": {
                        "data.cpu_usage_%": ["average", "max"],
                        "data.memory_usage_%": ["average", "max"]
                        } 
                },
                "train_config": {
                    #"window_size": 10, 
                    #"epochs" : 10
                },
                "display_name": "linux-resource-utilization-anomaly"
            }
            

        #self.orchestrate_training_a_detector(json_training_request) 
   
        # self.orchestrate_retrieving_all_detectors() 
        
        detector_id = "fcf3a873-34c8-42ca-8196-d8944fb4058c"
        
        # self.orchestrate_retrieving_a_detector(detector_id) 
        
        # Define sample prediction request JSON object 
        json_prediction_request = {
                "detector_id": detector_id, 
                "index_date": "2024-07-*", 
                "start_time": "2024-06-17T12:00:00Z", 
                "end_time": "2024-06-17T00:00:00Z"
            }
            
        # self.orchestrate_prediction(json_prediction_request)
        
        
    def __init__(self):
        """ 
        """ 
        
    def orchestrate_training_a_detector(self, json_training_request): 

        data_storage_manager = DataStorageManager() 
        data_storage_manager.save_detector_input_parameters(json_training_request) 
        data_retrieval_manager = DataRetrievalManager(data_storage_manager.uuid) 
            
        # Check if all required keys exist in json_training_request
        if all(key in json_training_request for key in ["columns", "index_date", "aggregation"]): 
            # Create an instance of WazuhDataIngestor 
            wazuh_data_ingestor = WazuhDataIngestor()
            
            # Retrieve the training data for the specified date and list of features 
            input_data, datasource_name = wazuh_data_ingestor.get_training_data(json_training_request.get("index_date"), settings.WAZUH_COLUMNS_PATH)
                    
            # Convert data types into proper format 
            input_data = DataTypeTransformer.transform_data_types(input_data, settings.WAZUH_COLUMNS_PATH) 
            
            # Preprocess the data 
            train_data, test_data, train_stamps, test_stamps = DataPreprocessor.preprocess(input_data, json_training_request, stateful=False)
            
            # Train a detector 
            train_response = train_MTAD_GAT(train_data, test_data, train_stamps, test_stamps, json_training_request.get("train_config", {}), test_labels=None) 

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
                "display_name": json_training_request.get("display_name", ""),
                "train_config": json_training_request.get("train_config", {}),
                "aggregation_config": json_training_request.get("aggregation_config", {}),
                "status": updated_detector_input_parameters["model_info"].get("status", ""),
                "errors": updated_detector_input_parameters["model_info"].get("errors", []),
                "diagnostics_info": {
                    "model_state": train_response
                    }
                }
            }  
                
            print("response: ", response)
        
            # destroy the singleton objects 
            DataStorageManager.destroy_instance()
            DataRetrievalManager.destroy_instance() 
        
        else:
            # Raise an exception if one or more required keys are missing
            missing_keys = [key for key in ["columns", "index_date", "aggregation", "train_config"] if key not in json_training_request]
            raise ValueError(f"Missing required keys in json_training_request: {', '.join(missing_keys)}")


 


    def orchestrate_prediction(self, json_prediction_request): #detecting_anomalies 
        # Check if all required keys exist in json_prediction_request
        if all(key in json_prediction_request for key in ["detector_id", "index_date", "start_time", "end_time"]): 
            # Create an instance of WazuhDataIngestor 
            wazuh_data_ingestor = WazuhDataIngestor()
            
            # Retrieve the prediction data for the specified date and list of features 
            prediction_data, datasource_name = wazuh_data_ingestor.get_training_data(json_prediction_request.get("index_date"), settings.WAZUH_COLUMNS_PATH)
                    
            # Convert data types into proper format 
            prediction_data = DataTypeTransformer.transform_data_types(prediction_data, settings.WAZUH_COLUMNS_PATH) 
            
            # Fetch the configurations for the provided detector 
            data_retrieval_manager = DataRetrievalManager(json_prediction_request.get("detector_id", "")) 
            detector_parameters = data_retrieval_manager.retrieve_detector_parameters() 
            
            # Create an object of the data storage manager to store input data (is it required?) 
            data_storage_manager = DataStorageManager() 

            # Preprocess the data 
            prediction_data, test_data, prediction_stamps, test_stamps = DataPreprocessor.preprocess(prediction_data, detector_parameters, test_split=0, stateful=False)
            
            # print(f"prediction_data: {prediction_data}")
            # print(f"test_data: {test_data}")
            # print(f"prediction_stamps: {prediction_stamps}")
            # print(f"test_stamps: {test_stamps}") 
            
            # Predict anomalies 
            pred_df, anomalies = predict_MTAD_GAT(prediction_data, prediction_stamps)
            #print("Anomalies:")
            #print(anomalies.index)
            #print(anomalies)

            # Add prediction code here, use prediction_data and prediction_stamps 
            response = ""
            print("response: ", response)
            
            # destroy the singleton objects 
            DataStorageManager.destroy_instance()
            DataRetrievalManager.destroy_instance()
 
        else:
            # Raise an exception if one or more required keys are missing
            missing_keys = [key for key in ["detector_id", "index_date", "start_time", "end_time"] if key not in json_prediction_request]
            raise ValueError(f"Missing required keys in json_training_request: {', '.join(missing_keys)}") 
        
        



    def orchestrate_retrieving_a_detector(self, detector_id:str): 
        # get a detector 
        
        data_retrieval_manager = DataRetrievalManager(detector_id) 
        detector = data_retrieval_manager.retrieve_detector_parameters() 
        print(detector) 
        # destroy the singleton objects 
        DataRetrievalManager.destroy_instance()

        
    def orchestrate_retrieving_all_detectors(self):  
        # get all detectors 
        
        detectors = retrieve_all_detector_parameters()
        print(detectors) 
        
        

def entry_point():
    """
    Module-level function to serve as the entry point.
    """
    orchestration = ADOrchestration()
    orchestration.main() 
    


if __name__ == "__main__": 
    orchestration = ADOrchestration() 
    print("Calling main method of orchestration class. ")
    orchestration.main() 
        


   