from siem_mtad_gat.data_manager.detectors import * 
import siem_mtad_gat.settings as settings
from siem_mtad_gat.data_manager.data_storage_manager import DataStorageManager 
from siem_mtad_gat.data_ingestion.wazuh.wazuh_data_ingestor import WazuhDataIngestor
from siem_mtad_gat.data_transformer import DataTypeTransformer
from siem_mtad_gat.data_transformer import DataPreprocessor
from siem_mtad_gat.data_manager.data_retrieval_manager import DataRetrievalManager 
from siem_mtad_gat.data_manager.spot_manager import SPOTManager
from siem_mtad_gat.mtad_gat_pytorch.train_alab import train_MTAD_GAT 
from siem_mtad_gat.mtad_gat_pytorch.predict_alab import predict_MTAD_GAT
from datetime import datetime 
from siem_mtad_gat.ad_engine.mtad_gat.detector import Detector
import logging 
import threading 
from typing import List
import os
os.makedirs(settings.OUTPUT_LOGS, exist_ok=True)
logging.basicConfig(filename=settings.LOGGING_FILE_NAME.format(name=__name__), filemode='a', format=settings.DEFAULT_LOGGING_FORMAT)
logger = logging.getLogger(__name__)
logger.setLevel(settings.DEFAULT_LOGGING_LEVEL) 

# TO-REDESIGN (generalize and make AD engine more (ML) algorithm agnostic; add agility and multiplexing, e.g., abstract out usage of MTAD-GAT and invoke it via a pluggable mechanism)
# TO-REDESIGN (reimplement run mode following a state design pattern)
# TO-REDESIGN (consolidate engine data source and logic concerns, e.g., ingestion, transformation calls encapsulated into distinct AD engine inner classes)
# TO-REDESIGN (consolidate all response object creation into a dedicated and reusable module, ideally inheriting from an abstract response creator)
# TO-DO (safety, e.g., avoid unsafe poking into array indices)

class ADEngine: 
    def __init__(self):
        """ 
        """     
        self.set_detectors_and_id()
    
    def set_detectors_and_id(self): 
        # Create a stack for detectors and fetch them 
        self.detectors = retrieve_all_detector_ids_sorted() 
        # Initiate detector id  
        if not len(self.detectors) == 0:
            self.current_detector_id =  self.detectors[-1] 
        else: 
            logging.info("No existing detectors found! train a detector.")
            print("No existing detectors found! train a detector.")    
            self.current_detector_id = None 
    
    def set_current_detector_id(self) -> str:        
        if not len(self.detectors) == 0:
            return self.detectors[-1] 
        else: 
            logging.info("No existing detectors found! train a detector.")  
            print("No existing detectors found! train a detector.") 
            return None 
        
    def set_detectors(self) -> List[str]:
        return retrieve_all_detector_ids_sorted() 
    
    
    def get_detectors(self): 
        return retrieve_all_detectors_info_sorted()
         
         
    def train(self, 
              index_date:str="default", 
              detector_name:str="default", 
              default_config:bool=True, 
              custom_config_file=None, 
              use_case_no=0): 
        
        logging.info("Calling train. ") 
        
        detector = Detector()        
        training_request = detector.get_detector_training_input(index_date, detector_name, default_config, custom_config_file) 
        if training_request is None: 
            return None 
                
        data_storage_manager = DataStorageManager() 
        data_storage_manager.save_detector_input_parameters(training_request)  
        data_retrieval_manager = DataRetrievalManager(data_storage_manager.uuid) 

         # Get use case number and generate a yaml file 
        if use_case_no == 0: 
            use_case_no = data_storage_manager.save_yaml_train(training_request)
             
            
        # Check if all required keys exist in training_request
        if all(key in training_request for key in ["columns", "index_date", "aggregation"]): 
            wazuh_data_ingestor = WazuhDataIngestor()
            
            train_data_result = wazuh_data_ingestor.get_training_data(training_request.get("index_date")) 
            if train_data_result is None:
                logging.error("get_training_data returned None. No Training data was fetched for given input.") 
                print("get_training_data returned None. No Training data was fetched for given input.") 
                return 
            
            # Retrieve the training data for the specified date and list of features 
            input_data, datasource_name = train_data_result
                    
            if not input_data: 
                logging.error("No data found for given input.")
                print("No data found for given input.")
                return  
            
            # Convert data types into proper format 
            input_data = DataTypeTransformer.transform_data_types(input_data, settings.WAZUH_COLUMNS_PATH) 
            
            # Preprocess the data 
            preprocess_result = DataPreprocessor.preprocess(input_data, 
                                                                                           training_request, 
                                                                                           stateful=False, 
                                                                                           caller="train") 
            
            if preprocess_result is None: 
                logging.error("No data after preprocessing.") 
                print("No data returned after preprocessing. The provided columns were not found in the fetched data.")
                return 
            
            train_data, test_data, train_stamps, test_stamps, column_names = preprocess_result 

            #Create SPOT manager
            n_features=train_data.shape[1]
            spot_manager=SPOTManager(n_features)

            # Train a detector 
            train_response = train_MTAD_GAT(train_data, 
                                            test_data, 
                                            train_stamps, 
                                            test_stamps, 
                                            training_request.get("train_config"), 
                                            test_labels=None) 


            updated_detector_input_parameters = {
             "detector_id" : data_storage_manager.uuid, 
             "created_time": datetime.now(settings.TIMEZONE).strftime(settings.DATE_TIME_FORMAT), 
             "last_updated_time": datetime.now(settings.TIMEZONE).strftime(settings.DATE_TIME_FORMAT),
             "model_info": { 
                   "datasource": datasource_name, 
                   "start_time": "",
                    "end_time": "", 
                    "status": "CREATED", 
                    "errors": []
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
                "display_name": training_request.get("display_name", ""),
                "train_config": training_request.get("train_config", {}),
                "aggregation_config": training_request.get("aggregation_config", {}),
                "status": updated_detector_input_parameters["model_info"].get("status", ""),
                "errors": updated_detector_input_parameters["model_info"].get("errors", []),
                "diagnostics_info": {
                    "model_state": train_response
                    }
                }
            }   
            
            
            # Change the current detector to this trained one after training 
            self.set_detectors_and_id()

            # save spot trained object
            spot_manager.save_all_train()
            
            # destroy the singleton objects 
            SPOTManager.destroy_instance
            DataStorageManager.destroy_instance()
            DataRetrievalManager.destroy_instance() 
            
            # return the response
            return response
        
        else:
            # Raise an exception if one or more required keys are missing
            missing_keys = [key for key in ["columns", "index_date", "aggregation", "train_config"] if key not in training_request]
            raise ValueError(f"Missing required keys in training_request: {', '.join(missing_keys)}")   
              
    def predict(self, 
                run_mode:str="default", 
                index_date:str="default", 
                detector_id:str="default", 
                start_time:str="default", 
                end_time:str="default", 
                batch_size:int=settings.DEFAULT_BATCH_SIZE, 
                predict_input_config=None, 
                use_case_no=0): 
        
        
        logging.info("Calling predict. ") 
        
        exec_timestamp = settings.CURRENT_TIMESTAMP
        # Create a detector object 
        detector = Detector()    
        
        if predict_input_config is not None: 
            run_mode, index_date, detector_id, start_time, end_time, batch_size = detector.parse_predict_config(predict_input_config)

        
        #run_mode = settings.RUN_MODE[run_mode]
        if run_mode == "default": 
            run_mode = settings.DEFAULT_RUN_MODE
         
        # Parse the run mode     
        run_mode = next(m for m in settings.RUN_MODE if m.name.lower() == run_mode.lower())  
        
        
        detector_id = self.current_detector_id if detector_id == "default" else detector_id 
        # print(detector_id) 

        if detector_id == None: 
            logging.error(f"No detector found for prediction. Train a detector")
            print(f"No detector found for prediction. Train a detector")
            return  
        
        # Fetch the configurations for the provided detector 
        data_retrieval_manager = DataRetrievalManager(detector_id) 
        detector_parameters = data_retrieval_manager.retrieve_detector_parameters() 
            
        # Create an object of the data storage manager to store input data 
        data_storage_manager = DataStorageManager(detector_id)  
        
        # Get granularity and window_size 
        granularity = self.__get_granularity(detector_parameters)
        window_size = self.__get_window_size(detector_parameters, data_retrieval_manager)
        
        # Get use case number and generate a yaml file 
        if use_case_no == 0: 
            use_case_no = data_storage_manager.save_yaml_predict(run_mode.name, index_date, detector_id, start_time, end_time, batch_size)
            
            
        # Get feature number
        n_features=self.__get_n_features(detector_parameters)
        #Create SPOT manager
        spot_manager=SPOTManager(n_features=n_features,load_obj=True)
        
        match run_mode:
            case settings.RUN_MODE.HISTORICAL:
                logging.info("Predicting in historical mode.")  
                print("Predicting in historical mode.")  
                
                # Get prediction request 
                prediction_request = detector.get_detector_prediction_input(run_mode=run_mode, 
                                                                                    index_date=index_date, 
                                                                                    start_time=start_time, 
                                                                                    end_time=end_time, 
                                                                                    granularity=granularity, 
                                                                                    window_size=window_size) 
                
                prediction_request["detector_id"] =  detector_id
                response = self.__run_predict(prediction_request, detector_parameters, run_mode, use_case_no, exec_timestamp)
                yield response


            case settings.RUN_MODE.BATCH:
                # Get batch_interval in minutes 
                batch_interval_minutes = detector.get_batch_interval_in_minutes(batch_size, granularity)
                batch_interval_seconds = batch_size * detector.get_granularity_in_seconds(granularity)
                # print(batch_interval_minutes)

                logging.info(f"Predicting in batch mode with batch interval {batch_interval_minutes} min = {batch_interval_seconds} sec . ")
                print(f"Predicting in batch mode with batch interval {batch_interval_minutes} min = {batch_interval_seconds} sec. ")
                

                
                
                #Run initial request 
                prediction_request = detector.get_detector_prediction_input(run_mode=run_mode, 
                                                                                    granularity=granularity, 
                                                                                    window_size=window_size, 
                                                                                    batch_size=batch_size) 
                
                prediction_request["detector_id"] =  detector_id
                # print(prediction_request)
                response = self.__run_predict(prediction_request, detector_parameters, run_mode, use_case_no, exec_timestamp)
                
                if response == None: 
                    return 
                
                yield response 
                # Keep running the batch requests 
                try: 
                    ticker = threading.Event()
                    while not ticker.wait(timeout=batch_interval_seconds): # Give timeout in seconds 
                        # Get prediction request 
                        prediction_request = detector.get_detector_prediction_input(run_mode=run_mode, 
                                                                                    granularity=granularity, 
                                                                                    window_size=window_size, 
                                                                                    batch_size=batch_size) 
                
                        prediction_request["detector_id"] =  detector_id
                        response = self.__run_predict(prediction_request, detector_parameters, run_mode, use_case_no, exec_timestamp)
                        
                        if response == None: 
                            return 
                        
                        yield response  
                        

                except Exception as e:
                    logging.error(f"An error occurred in prediction: {str(e)}")      
                
                

            case settings.RUN_MODE.REALTIME:
                real_time_interval_minutes = detector.get_granularity_in_minutes(granularity) 
                real_time_interval_seconds = detector.get_granularity_in_seconds(granularity) 
                
                logging.info(f"Predicting in real-time mode with interval {real_time_interval_minutes} min = {real_time_interval_seconds} sec. ")
                print(f"Predicting in real-time mode with interval {real_time_interval_minutes} min = {real_time_interval_seconds} sec. ") 

                # running the realtime requests 
                try: 
                    ticker = threading.Event()
                    # For realtime the interval is 1 minute 
                    while not ticker.wait(timeout=real_time_interval_seconds): # Give timeout in seconds 
                        # Get prediction request 
                        prediction_request = detector.get_detector_prediction_input(run_mode=run_mode, 
                                                                                    granularity=granularity, 
                                                                                    window_size=window_size) 
                
                        prediction_request["detector_id"] =  detector_id
                        print(prediction_request)
                        response = self.__run_predict(prediction_request, detector_parameters, run_mode, use_case_no, exec_timestamp)
                        if response == None: 
                            return 
                        
                        yield response 

                except Exception as e:
                    logging.error(f"An error occurred in prediction: {str(e)}")      
                     
            case _:
                logging.error("Invalid run mode.") 
                 
                 
        # destroy the singleton objects
        SPOTManager.destroy_instance 
        DataStorageManager.destroy_instance()
        DataRetrievalManager.destroy_instance()
        
      
        
    # Declaring private method for running prediction. 
    def __run_predict(self, prediction_input, detector_parameters, run_mode, use_case_no, exec_timestamp): 
        # Check if all required keys exist in prediction_request
        if all(key in prediction_input for key in ["detector_id", "index_date", "start_time", "end_time"]): 
                                
            # Create an instance of WazuhDataIngestor 
            wazuh_data_ingestor = WazuhDataIngestor()
                    
            # Retrieve the prediction data for the specified date and list of features 
            prediction_data = wazuh_data_ingestor.get_prediction_data(prediction_input.get("index_date"),  
                                                                            prediction_input.get("start_time"),
                                                                            prediction_input.get("end_time"), 
                                                                            run_mode)
                        
            if not prediction_data: 
                logging.error("No data found for given input.")
                print("No data found for given input.") 
                return 
                                        
            # Convert data types into proper format 
            prediction_data = DataTypeTransformer.transform_data_types(prediction_data, settings.WAZUH_COLUMNS_PATH) 
                                
            # Preprocess the data 
            
            
            preprocess_result = DataPreprocessor.preprocess(prediction_data, 
                                                            detector_parameters, 
                                                            test_split=0, 
                                                            stateful=False, 
                                                            caller="predict")
                 
            if preprocess_result is None: 
                logging.error("No data after preprocessing.") 
                print("No data returned after preprocessing. The provided columns were not found in the fetched data.")
                return 
            
            prediction_data, test_data, prediction_stamps, test_stamps, column_names = preprocess_result  
               
            # Predict anomalies 
            pred_result = predict_MTAD_GAT(prediction_data, prediction_stamps) 
            # Check if result is None 
            if pred_result is None:
                logging.error("predict_MTAD_GAT returned None.") 
                print("The output of prediction was None.")
                return 
                
            pred_df, anomalies = pred_result 
                    
            predicted_anomalies_data = self.__build_response(prediction_input, anomalies, column_names)
            predicted_data = self.__build_response(prediction_input, pred_df, column_names)
            
            
            # Save response before returning 
            data_storage_manager = DataStorageManager()
            data_storage_manager.save_predict_output(predicted_anomalies_data, use_case_no, exec_timestamp, output_type="predicted_anomalies_data")  
            data_storage_manager.save_predict_output(predicted_data, use_case_no, exec_timestamp, output_type="predicted_data")  

 
            return predicted_anomalies_data 
                    
        else:
            # Raise an exception if one or more required keys are missing
            missing_keys = [key for key in ["detector_id", "index_date", "start_time", "end_time"] if key not in prediction_input]
            raise ValueError(f"Missing required keys in json_training_request: {', '.join(missing_keys)}") 
        


    # Declaring private method to get granularity. 
    def __get_granularity(self, detector_parameters): 
         # Retrieve the value of 'granularity' from the 'detector_parameters' dictionary.
        try:
            granularity = detector_parameters["aggregation_config"]["granularity"] 
            return granularity 
        except KeyError as e:
            raise KeyError("The key 'granularity' does not exist in 'aggregation_config'.") from e  
        
        
    # Declaring private method to get window size. 
    def __get_window_size(self, detector_parameters, data_retrieval_manager:DataRetrievalManager):  
        # Check if train_config is empty
        if not detector_parameters.get("train_config"): 
            training_config = data_retrieval_manager.retrieve_training_config()
            if "window_size" not in training_config:
                raise ValueError("Window size not found in training configuration")
            window_size = training_config["window_size"] 
        else:
            window_size = detector_parameters["train_config"]["window_size"] 
            
        # Ensure window_size is valid
        if window_size is None:
                raise ValueError("Window size is None, could not be determined. ") 
        
        return window_size  
    

    # Declaring private method to get number of features. 
    def __get_n_features(self, detector_parameters): 
        try:
            if detector_parameters.get("aggregation",bool):
                fe=detector_parameters.get("aggregation_config").get("features")
                return sum(len(fe[k]) for k in fe)
            else: 
                logging.error("Not aggregated data not implemented." )
        except KeyError as e:
            logging.error("The key 'aggregation' does not exist." )
        
     


    def __build_response(self, prediction_input, dataframe, column_names): 
        # Building the JSON object
        response = {
                "run_mode": prediction_input.get("run_mode"),
                "detector_id": prediction_input.get("detector_id"),
                "index_date": prediction_input.get("index_date"),
                "start_time": prediction_input.get("start_time"),
                "end_time": prediction_input.get("end_time"),
                "results": []
        } 
            
        # Create a mapping from numeric suffix to column names
        mapping = {str(i): name for i, name in enumerate(column_names)}
            
        results = []
        for index, row in dataframe.iterrows():
            # Extracting values for A_Pred_Global and A_Score_Global from the current row
            is_anomaly = bool(row['A_Pred_Global'])
            score = row['A_Score_Global']
            # Constructing the value dictionary dynamically
            prediction_values = {column: row[column] for column in row.index} 
            updated_prediction_values = {}
            # Iterate through prediction_values to replace keys
            for key, value in prediction_values.items():
                for suffix, col_name in mapping.items():
                    if f"_{suffix}" in key:
                        new_key = key.replace(f"_{suffix}", f"_{col_name}")
                        updated_prediction_values[new_key] = value
                        break
                else:
                    # For keys that do not have a suffix, retain them as is
                    updated_prediction_values[key] = value
 
 
            timestamp = index.strftime(settings.DATE_TIME_FORMAT)
            result_entry = {
                    "timestamp": timestamp,
                    "is_anomaly": is_anomaly,
                    "score": score,
                    "prediction_values": updated_prediction_values
                    }
                
            results.append(result_entry)    
        
        response["results"] = results
                
        return response
                
    def select(self, detector_id:str): 
        logging.info("Calling select. ") 
        self.current_detector_id = detector_id 


 