import logging 
import os
import threading

import numpy as np
import pandas as pd 


import siem_mtad_gat.config_manager.config_keys as keys
from siem_mtad_gat.request_response_handler.keys import RESP_RESULTS
from siem_mtad_gat.ad_engine.mtad_gat import *

from pandas.core.frame import DataFrame
from datetime import datetime 
from typing import Dict, Generator, List, Tuple
from siem_mtad_gat.commons import EscapeError, EscapeInfo, EscapeWarning
from siem_mtad_gat.config_manager.config_manager import DetectorConfigManager
from siem_mtad_gat.data_manager.detectors import retrieve_all_detector_ids_sorted, retrieve_all_detectors_info_sorted
from siem_mtad_gat.data_manager.data_storage_manager import DataStorageManager 
from siem_mtad_gat.data_ingestion.wazuh.wazuh_data_ingestor import WazuhDataIngestor
from siem_mtad_gat.data_transformer import DataTypeTransformer
from siem_mtad_gat.data_transformer import DataPreprocessor
from siem_mtad_gat.data_manager.data_retrieval_manager import DataRetrievalManager 
from siem_mtad_gat.data_manager.spot_manager import SPOTManager
from siem_mtad_gat.mtad_gat_pytorch.train_alab import train_MTAD_GAT 
from siem_mtad_gat.mtad_gat_pytorch.predict_alab import predict_MTAD_GAT
from siem_mtad_gat.shipper.wazuh_data_shipper import CREATE, WazuhDataShipper
from siem_mtad_gat.time_manager import RUNMODE_ERROR, TimeManager
import siem_mtad_gat.request_response_handler.response_handler as response_handler
import siem_mtad_gat.request_response_handler.request_handler as request_handler

# TO-REDESIGN (generalize and make AD engine more (ML) algorithm agnostic; add agility and multiplexing, e.g., abstract out usage of MTAD-GAT and invoke it via a pluggable mechanism)
# TO-REDESIGN (reimplement run mode following a state design pattern)
# TO-REDESIGN (consolidate engine data source and logic concerns, e.g., ingestion, transformation calls encapsulated into distinct AD engine inner classes)
# TO-REDESIGN (consolidate all response object creation into a dedicated and reusable module, ideally inheriting from an abstract response creator)
# TO-DO (safety, e.g., avoid unsafe poking into array indices)

ERROR_KEYS="Missing required keys in training_request: {missing_keys}"
ERROR_INGESTION1="get_training_data returned None. No Training data was fetched for given input."
ERROR_INGESTION2="No data was fetched for given input."
ERROR_PREPROC="No data returned after preprocessing. The provided columns were not found in the fetched data."
ERROR_TRAIN_REQUEST_NONE= "Training request is None"
ERROR_PRED_REQUEST_NONE= "Prediction request is None"
ERROR_PREDICTION_WITH_NO_DETECTORS="No detector found for prediction. Train a detector"
ERROR_PREDICTION_EMPTY_DETECTORS="The list of detectors is empty! The prediction pipeline can be initiate only if at least a detector is available!"
ERROR_DETECTOR_NOT_AVAILABLE="The detector {id} does not exist!"
PREDICTION_RESPONSE = "Prediction response:"

UC_LIST_MAP={
    settings.RUN_MODE.BATCH : keys.UC_BATCH_LIST,
    settings.RUN_MODE.REALTIME : keys.UC_REALTIME_LIST,
    settings.RUN_MODE.HISTORICAL : keys.UC_HISTORICAL_LIST
}

OUT_TYPE_ANOMALIES="predicted_anomalies_data"
OUT_TYPE_PRED="predicted_data"

DETECTOR_STREAM="detector_stream"

class ADEngine:
    """ 
    The anomaly detection engine is the core component of ADBox. In fact, for every available anomaly detection method it orchestrates the interaction between the bulk functions of every algorithm, the data ingestion, data storage, user output, etc. In other words, the Engine determines the sequence of action to be performed to successfully go through the detection pipeline.

    Attributes:
        detectors (List[str]): List of detector IDs.
        current_detector_id (str): uuid of the currently selected detector.
        transform_columns_path (str): 
        algorithm (str): algorithm used by pipelines
        default_config_path (str): default detector configuration's path
        test_env(bool): If set True, the engine gathers assets (e.g., uc) from test environment.
        ship_to_indexer (bool): If True, ship data to Wazuh.        
    """     
    def __init__(self,ship_to_indexer:bool=False):
        """
        Initializes the ADEngine class and sets up the detector system by retrieving 
        the list of detectors and setting the current detector ID to the latest one.
        Then configures default paths and the algorithm to be used.

        Args. 
            ship_to_indexer (bool): If True, ship data to Wazuh. Default False.
        """
        self.set_detectors_and_id()
        self.transform_columns_path: str=settings.WAZUH_COLUMNS_PATH
        self.algorithm=settings.MTAD_GAT
        self.default_config_path: str=settings.DEFAULT_DETECTOR_INPUT_CONFIG
        self.test_env=False
        self.ship_to_indexer=ship_to_indexer

    
    def set_detectors_and_id(self): 
        """
        Retrieves and sets the list of available detectors. If detectors are available,
        sets the current detector to the latest one. 
        """        
        # Create a stack for detectors and fetch them 
        self.detectors = retrieve_all_detector_ids_sorted() 
        # Initiate detector id  
        if not len(self.detectors) == 0:
            self.current_detector_id =  self.detectors[-1] 
        else: 
            EscapeInfo("No existing detectors found! train a detector.",logger) 
            self.current_detector_id = None 
    
    def set_current_detector_id(self) -> str|None: 
        "Returns the last trained detector"      
        if not len(self.detectors) == 0:
            return self.detectors[-1] 
        else: 
            EscapeInfo("No existing detectors found! train a detector.",logger)  
            return None 
        
    def set_detectors(self) -> List[str]:
        """
        Retrieves and returns a list of all detectors' id sorted by time
        """
        return retrieve_all_detector_ids_sorted() 
    
    
    def get_detectors(self):
        """
        Retrieves and returns a list of all detectors' id sorted by time and their info
        """ 
        return retrieve_all_detectors_info_sorted()

    def get_training_requests_from_uc(self,uc_number:int|None=None):
        """
        Calls the config manager to retrieve training configs.
        The corresponding pipeline should start if and only if the dictionary is non None.
       
        Args:
            uc_number (int or None): use-case number (expected uc-{uc_number}.yaml file in drivers folder). 
                        If None, the manager returns default configuration.
        
        Returns:
            dict or None: training configs. 
        """
        dcm=DetectorConfigManager(self.current_detector_id,default_config_path=self.default_config_path,use_case_number=uc_number)
        if self.test_env: dcm.yaml_file=settings.TEST_UC_YAML.format(number=uc_number)
        return dcm.get_train_config_from_uc_yaml()

    def get_prediction_requests_from_uc(self,uc_number:int|None=None):
        """
        Calls the config manager to retrieve prediction configs.
        The corresponding pipeline should start if and only if the dictionary is non None.
       
        
        Args:
            uc_number (int or None): use-case number (expected uc-{uc_number}.yaml file in drivers folder). 
                        If None, the manager returns default configuration.
        
        Returns:
            dict or None: prediction configs.
        """
        dcm=DetectorConfigManager(self.current_detector_id,default_config_path=self.default_config_path,use_case_number=uc_number)
        if self.test_env: dcm.yaml_file=settings.TEST_UC_YAML.format(number=uc_number)
        return dcm.get_predict_config_from_uc_yaml()
         
    def training_pipeline(self, training_request:dict|None) -> dict | None :
        """
        Runs the training pipeline. Algorithm, shipping settings, etc. depends on the current state of the engine.

        Args.
         training_request (dict or None): Training configuration, it should be generated by using the method `get_training_requests_from_uc`.
                                        If None the pipeline should return None.
        
        Returns:
            dict or None: Stastics about training.                               
        """
        if training_request is None: 
            EscapeInfo(ERROR_TRAIN_REQUEST_NONE,logger)
            return
        
        EscapeInfo("Start training pipeline.",logger) 
        
        #check necessary keys existence
        if not all(key in training_request for key in keys.UC_TRAINING_LIST): 
            # Raise an exception if one or more required keys are missing
            missing_keys = [key for key in keys.UC_TRAINING_LIST if key not in training_request]
            raise ValueError(f"Missing required keys in training_request: {', '.join(missing_keys)}")   
             
        #detector = Detector()        
        EscapeInfo("Init Data managers.",logger)         
        data_storage_manager = DataStorageManager() 
        data_storage_manager.save_detector_input_parameters(training_request)  
        data_retrieval_manager = DataRetrievalManager(data_storage_manager.uuid) 

        # Get use-case number and generate a yaml file 
        #if use_case_no == 0: 
        #    use_case_no = data_storage_manager.save_yaml_train(training_request)
        EscapeInfo("Data ingestion.",logger)      
        ingested_data, datasource_name=self.ingest_training(training_request) # TO-DO: unify ingestion
        EscapeInfo("Data transformation.",logger)    
        transformed_data=self.transform(training_request,ingested_data)
        _, _, _, _, column_names = transformed_data  
        EscapeInfo("Start train.",logger) 
        train_response,train_out_df,test_out_df=self.train(training_request,transformed_data)

        # prepare and store training params dictionary
        training_params = response_handler.training_params(data_storage_manager.uuid,datasource_name)
        data_storage_manager.update_detector_input_parameters_after_training(training_params)

        # Change the current detector to this trained one after training 
        self.set_detectors_and_id()

        # prepare response
        response=response_handler.training_pipeline_response(training_request=training_request,train_response=train_response,training_params=training_params)

        if self.ship_to_indexer: 
            #ATM The shipping of training data is disabled to limit memory use to turn on set as True either ship_train and/or ship_test
            detector_stream=self.__ship_to_wazuh_training_pipeline(column_names=column_names,train_out_df=train_out_df,test_out_df=test_out_df,ship_train=False,ship_test=False)
            

        # destroy the singleton objects 

        DataStorageManager.destroy_instance()
        DataRetrievalManager.destroy_instance() 
        
        # return the response
        return response

    def prediction_pipeline(self,prediction_request:dict|None,uc_number:int) -> Generator:
        """
        Runs the prediction pipeline. Algorithm, shipping settings, etc. depends on the current state of the engine.

        Args.
            prediction_request (dict or None): Prediction configuration, it should be generated by using the method `get_prediction_requests_from_uc`.
                                        If None the pipeline should return None.
            uc_number: use-case number.
        Returns:
            Generator: prediction response generator.                               
        """
        if self.detectors==[] or self.detectors is None:
            self.destroy_all_singletons() 
            raise EscapeError(ERROR_DETECTOR_NOT_AVAILABLE,logger)

        if prediction_request is None: 
            EscapeInfo(ERROR_PRED_REQUEST_NONE,logger)
            self.destroy_all_singletons()
            return

            
        exec_timestamp: str = TimeManager.now_str()
        
        EscapeInfo("Start prediction pipeline. Detector: " + str(self.current_detector_id) ,logger) 

        # get runmode
        runmode=prediction_request.get(keys.UC_RUN_MODE)
        keys_list:list[str]=UC_LIST_MAP.get(runmode,[])

        #check necessary keys existence
        if not all(key in prediction_request for key in keys_list): 
            # Raise an exception if one or more required keys are missing
            missing_keys = [key for key in keys_list if key not in prediction_request]
            raise ValueError(f"Missing required keys in prediction_request: {', '.join(missing_keys)}")   
             
        EscapeInfo("Init Data managers.",logger)
        
        # detector id
        detector_id=prediction_request.get(keys.UC_DETECTOR_ID)

        if detector_id is None: 
            raise EscapeError(ERROR_PREDICTION_WITH_NO_DETECTORS,logger)

            

        # Fetch the configurations for the provided detector 
        data_retrieval_manager = DataRetrievalManager(detector_id) 
        detector_parameters = data_retrieval_manager.retrieve_detector_parameters()
        prediction_request.update(detector_parameters) 
            
        # Create an object of the data storage manager to store input data 
        data_storage_manager = DataStorageManager(detector_id)    
        
        # Get granularity and window_size 
        granularity = self.__get_granularity(detector_parameters)
        window_size = self.__get_window_size(detector_parameters, data_retrieval_manager)      
        # Get feature number
        n_features=self.__get_n_features(detector_parameters)
        self.__last_n_features=n_features

        # detector_Stream
        detector_stream=detector_parameters.get(DETECTOR_STREAM)
        if self.ship_to_indexer and detector_stream is None:
          raise EscapeWarning(f"Shipping to Wazuh not possible! No data stream associated to detector{detector_id}")

        if self.algorithm is settings.MTAD_GAT:
            condition_caller = (runmode in settings.CALLER_ONLINE_MODES) and os.path.exists(settings.SPOT_ONLINE_STORAGE_FOLDER.format(id=data_retrieval_manager.detector_id))
            caller= settings.CALLER_ONLINE if condition_caller else settings.CALLER_OFFLINE
            spot_manager=SPOTManager(n_features=n_features,load_obj=True,caller=caller)

        match runmode:
            case settings.RUN_MODE.HISTORICAL:
                EscapeInfo("Predicting in historical mode.",logger)  

                (start_fetch,end_fetch),(start_time_out,end_out)=TimeManager.get_intervals_historical(request_start_time=prediction_request.get(keys.UC_START_TIME,""),
                                                                                                      request_end_time=prediction_request.get(keys.UC_END_TIME,""),
                                                                                                      granularity=granularity,
                                                                                                      window_size=window_size)

                response = self.__prediction_pipeline_body(prediction_request, exec_timestamp,start_fetch,end_fetch,uc_number,out_interval_extrema=(start_time_out,end_out),detector_stream=detector_stream)
                yield response
                # destroy the singleton objects
                self.destroy_all_singletons() #remove ?
                return

            case settings.RUN_MODE.BATCH:
                batch_size=prediction_request.get(keys.UC_BATCH_SIZE,0)
                # Get batch_interval in minutes 
                batch_interval_minutes = TimeManager.get_batch_interval(batch_size=batch_size,
                                                                        granularity=granularity,
                                                                        window_size=window_size)
                batch_interval_seconds = batch_interval_minutes * 60
                batch_shift=TimeManager.batch_shift(batch_size=batch_size,granularity=granularity)

                EscapeInfo(f"Predicting in batch mode with batch interval {batch_interval_minutes} min = {batch_interval_seconds} sec . ",logger)

                
                request_time=TimeManager.now_str()
                end_fetch:str=TimeManager.timestamp_to_str(TimeManager.get_end_time_fetch_timestamp_online(granularity=granularity,time=request_time))
                start_fetch:str=TimeManager.get_start_time_fetch(run_mode=runmode,granularity=granularity,batch_size=batch_size,window_size=window_size,time=request_time)
                out_interval_extrema=TimeManager.get_output_interval_batch(time=request_time,granularity=granularity,batch_size=batch_size)

                wait_end_time_unit=TimeManager._diff_timestamps_seconds(TimeManager.str_to_timestamp(end_fetch),TimeManager.str_to_timestamp(request_time))
                # Keep running the batch requests
                try: 
                    ticker = threading.Event()
                    ticker.wait(timeout=wait_end_time_unit)
                    response = self.__prediction_pipeline_body(prediction_request, exec_timestamp,start_fetch,end_fetch,uc_number,out_interval_extrema,detector_stream=detector_stream)
                except Exception as e:
                    raise EscapeError(f"An error occurred in prediction: {str(e)}",logger) 

                
                if response is None:
                    self.destroy_all_singletons()  # remove?
                    return 
                yield response 
                # Keep running the batch requests 
                try: 
                    ticker = threading.Event()
                    while not ticker.wait(timeout=batch_shift): # Give timeout in seconds 
                        # Get prediction request 
                        request_time=TimeManager.next_batch_request(request=request_time,batch_shift=batch_shift)
                        end_fetch:str=TimeManager.timestamp_to_str(TimeManager.get_end_time_fetch_timestamp_online(granularity=granularity,time=request_time))
                        start_fetch:str=TimeManager.get_start_time_fetch(run_mode=runmode,granularity=granularity,batch_size=batch_size,window_size=window_size,time=request_time)
                        out_interval_extrema=TimeManager.get_output_interval_batch(time=request_time,granularity=granularity,batch_size=batch_size)
                        

                        response = self.__prediction_pipeline_body(prediction_request, exec_timestamp,start_fetch,end_fetch,uc_number,out_interval_extrema=out_interval_extrema,detector_stream=detector_stream)
                        if response is None:
                            self.destroy_all_singletons() 
                            return 
                        
                        yield response  
                except Exception as e:
                    raise EscapeError(f"An error occurred in prediction: {str(e)}",logger)

            case settings.RUN_MODE.REALTIME:
                real_time_interval_minutes: int | float = TimeManager.get_granularity_in_minutes(granularity)
                real_time_interval_seconds: float | int = TimeManager.get_granularity_in_seconds(granularity)

                EscapeInfo(f"Predicting in real-time mode with interval {real_time_interval_minutes} min = {real_time_interval_seconds} sec. ",logger)
                
                #First request
                request_time: str=TimeManager.now_str()
                end_fetch:str=TimeManager.timestamp_to_str(TimeManager.get_end_time_fetch_timestamp_online(granularity=granularity,time=request_time))
                start_fetch:str=TimeManager.get_start_time_fetch(run_mode=runmode,granularity=granularity,window_size=window_size,time=request_time)
                out_interval_extrema: Tuple[str,str]=TimeManager.get_output_interval_batch(time=request_time,granularity=granularity,batch_size=1)

                
                try: 
                    ticker = threading.Event()
                    # For realtime the interval is 1 minute
                    while not ticker.wait(timeout=real_time_interval_seconds): # Give timeout in seconds
                        # Get prediction 
                        response:dict = self.__prediction_pipeline_body(prediction_request, exec_timestamp,start_fetch,end_fetch,uc_number,out_interval_extrema=out_interval_extrema,detector_stream=detector_stream)
                        if response is None:
                            self.destroy_all_singletons() # remove?
                            return
                        # refreshing the realtime requests
                        request_time=TimeManager.next_batch_request(request=request_time,batch_shift=real_time_interval_seconds)
                        end_fetch:str=TimeManager.timestamp_to_str(TimeManager.get_end_time_fetch_timestamp_online(granularity=granularity,time=request_time))
                        start_fetch:str=TimeManager.get_start_time_fetch(run_mode=runmode,granularity=granularity,window_size=window_size,time=request_time)
                        out_interval_extrema=TimeManager.get_output_interval_batch(time=request_time,granularity=granularity,batch_size=1)
                        yield response


                except Exception as e:
                   raise EscapeError(f"An error occurred in prediction: {str(e)}",logger)      
                     
            case _:
                raise EscapeError(RUNMODE_ERROR,logger)

    
    # Declaring private method for running prediction.
    def __prediction_pipeline_body(self, prediction_request:dict,
                                   exec_timestamp:str,start_fetch:str,
                                   end_fetch:str,uc_number:int,
                                   out_interval_extrema:tuple[str,str],
                                   detector_stream:str) -> dict:
        """
        Runs the body of the prediction pipeline
        Args:
            prediction_request (dict): The prediction request parameters.
            exec_timestamp (str): The timestamp representing when the prediction pipeline was executed.
            start_fetch (str): The start time or date from which data will be fetched for the prediction. For time string's format see TimeManager. 
            end_fetch (str): The end time or date until which data will be fetched for the prediction. For time string's format see TimeManager. 
            uc_number (int): The use-case number.
            out_interval_extrema (tuple[str, str]): A tuple containing the start and end extrema of the output interval.
            detector_stream (str): The name of the detector stream to ship the output to. (Effective only if self.ship_to_indexer is True).

        Returns:
            dict: detected anomalies and info
        """
                                
        EscapeInfo("Data ingestion.",logger)      
        ingested_data=self.ingest_prediction(request=prediction_request,start_time=start_fetch,end_time=end_fetch) # TO-DO: unify ingestion
        EscapeInfo("Data transformation.",logger)    
        transformed_data=self.transform(prediction_request,ingested_data,caller=settings.CALLER_PREDIC)
        _, _, _, _, column_names = transformed_data   
        EscapeInfo("Predict.",logger) 
        pred_df, anomalies=self.predict(transformed_data)                

        predicted_anomalies_data = response_handler.prediction_pipeline_response(prediction_request=prediction_request, dataframe=anomalies, column_names=column_names,out_interval_extrema=out_interval_extrema,algorithm=self.algorithm)
        predicted_data = response_handler.prediction_pipeline_response(prediction_request=prediction_request, dataframe=pred_df, column_names=column_names,out_interval_extrema=out_interval_extrema,algorithm=self.algorithm)
            
        if self.ship_to_indexer and detector_stream is not None:
            self.__ship_to_wazuh_prediction_pipeline(predicted_data,detector_stream)
        # Save response before returning
        data_storage_manager = DataStorageManager()
        data_storage_manager.save_predict_output(output=predicted_anomalies_data,exec_timestamp=exec_timestamp,use_case_no=uc_number, output_type=OUT_TYPE_ANOMALIES)  
        data_storage_manager.save_predict_output(output=predicted_data, use_case_no=uc_number, exec_timestamp=exec_timestamp, output_type=OUT_TYPE_PRED)  

        return predicted_anomalies_data
                    
    def run_prediction_pipeline(self,prediction_request:dict|None,uc_number:int):
        """
        Runs the prediction pipeline's loop. Algorithm, shipping settings, etc. depends on the current state of the engine.

        Args.
            prediction_request (dict or None): Prediction configuration, it should be generated by using the method `get_prediction_requests_from_uc`.
                                        If None the pipeline should return None.
            uc_number: use-case number.  
        """

        prediction_generator:Generator = self.prediction_pipeline(prediction_request=prediction_request,uc_number=uc_number)
        try:
            for res in prediction_generator:
                print(PREDICTION_RESPONSE)
                print(str(res))
        except KeyboardInterrupt:
            EscapeInfo("Prediction pipeline interrupted by the user")
            runmode=prediction_request.get(keys.UC_RUN_MODE)
            if runmode in settings.CALLER_ONLINE_MODES and self.algorithm==settings.MTAD_GAT:
                sm=SPOTManager()
                sm.save_online()
            self.destroy_all_singletons()

        finally:
            EscapeInfo("Prediction ended")

    # Declaring private method to get granularity. 
    def __get_granularity(self, detector_parameters): 
        # Retrieve the value of 'granularity' from the 'detector_parameters' dictionary.
        granularity = detector_parameters.get(keys.UC_AGGREGATION_CONFIG).get(keys.UC_GRANULARITY) 
        if granularity is None: raise KeyError("The key 'granularity' does not exist in 'aggregation_config'.") 
        return granularity 
        
    # Declaring private method to get window size. 
    def __get_window_size(self, detector_parameters, data_retrieval_manager:DataRetrievalManager):  
        # Check if train_config is empty
        if not detector_parameters.get(keys.UC_TRAIN_CONFIG): 
            training_config :dict = data_retrieval_manager.retrieve_training_config()
            if keys.UC_WINDOW_SIZE not in training_config:
                raise ValueError("Window size not found in training configuration")
            window_size = training_config[keys.UC_WINDOW_SIZE] 
        else:
            window_size = detector_parameters[keys.UC_TRAIN_CONFIG][keys.UC_WINDOW_SIZE] 
            
        # Ensure window_size is valid
        if window_size is None:
                raise ValueError("Window size is None, could not be determined. ") 
        
        return window_size  
    

    # Declaring private method to get number of features. 
    def __get_n_features(self, detector_parameters) -> int: 
        """
        Returns the number of features
        """
        try:
            if detector_parameters.get(keys.UC_AGGREGATION,bool):
                fe=detector_parameters.get(keys.UC_AGGREGATION_CONFIG).get(keys.UC_FEATURES)
                return sum(len(fe[k]) for k in fe)
            else: 
                raise EscapeError("Not aggregated data not implemented.",logger )
        except:
            raise EscapeError(f"The key {keys.UC_AGGREGATION} does not exist.",logger)
         
                
    def select(self, detector_id:str):
        """
        Set self.current_detector_id to input id.
        """
        EscapeInfo("Calling select.",logger) 
        self.current_detector_id: str = detector_id 

    def ingest_training(self,request:dict) -> Tuple[List[Dict], str]: 
        """
        Ingestion operation for training pipeline
        Args:
            request (str): training request
        Returns:
            Tuple[List[Dict], str]: ingested data, source name
        """
        wazuh_data_ingestor = WazuhDataIngestor()
        index:str=request.get(keys.UC_INDEX_DATE,"")
        train_data_result = wazuh_data_ingestor.get_training_data(index) 
        if train_data_result is None:
            raise EscapeError(ERROR_INGESTION1,logger) 
        # Retrieve the training data for the specified date and list of features 
        input_data, _= train_data_result
                
        if not input_data: 
            raise EscapeError(ERROR_INGESTION2,logger)
            #raise(Exception(ERROR_INGESTION2))
        return train_data_result
    
    def ingest_prediction(self,request:dict,start_time:str,end_time:str): 
        """
        Ingestion operation for prediction pipeline
        Args:
            request (str): prediction request
            start_time (str): The start time or date from which data will be fetched for the prediction. For time string's format see TimeManager. 
            end_time (str): The end time or date until which data will be fetched for the prediction. For time string's format see TimeManager. 
            
        Returns:
            List[Dict]: ingested data
        """
        runmode=request.get(keys.UC_RUN_MODE)
        # Create an instance of WazuhDataIngestor 
        wazuh_data_ingestor = WazuhDataIngestor()
            
        # Retrieve the prediction data for the specified date and list of features 
        prediction_data = wazuh_data_ingestor.get_prediction_data(start_time=start_time,end_time=end_time,run_mode=runmode,date="*-*-*")
                        
        if not prediction_data: 
            raise EscapeError(ERROR_INGESTION2,logger)
            #raise(Exception(ERROR_INGESTION2))

        return prediction_data




    def transform(self,request:dict,
                  data:List[Dict],
                  caller:str=settings.CALLER_TRAIN) -> Tuple[np.ndarray,np.ndarray|None,pd.Index,pd.Index,pd.Index]:
        """
        Transform ingested data in data consumable by ML algorithm.
        This includes:
            - data type transformation
            - preprocessing

        Args:
            request (str): prediction/training request
            data (List[Dict]): ingested data
            caller (str): the pipeline calling the preprocessing. 
                        This shall be either settings.CALLER_TRAIN or settings.CALLER_PREDIC.

        Returns:
            Tuple[pd.DataFrame,pd.DataFrame,pd.Index,pd.Index]: 
                (train data, test data, train data timestamps, test timestamps)
        """
        # Convert data types into proper format 
        input_data: pd.DataFrame = DataTypeTransformer.transform_data_types(data, self.transform_columns_path)

        split:float=settings.TEST_SPLIT if caller == settings.CALLER_TRAIN else 0

        # Preprocess the data
        preprocess_result: Tuple[np.ndarray,np.ndarray|None,pd.Index,pd.Index,pd.Index]= DataPreprocessor.preprocess(input_data=input_data,
                                                                                            input_config=request,
                                                                                            test_split=split,
                                                                                            stateful=False,
                                                                                            caller=caller)
        
        if preprocess_result is None:
            raise EscapeError(ERROR_PREPROC,logger)

        return preprocess_result

    def train(self,request,preprocessed_data:Tuple[np.ndarray,np.ndarray|None,pd.Index,pd.Index,pd.Index]):
        """
        Runs the training of the detector using the algorithm self.algorithm
        Args:
            preprocessed_data  (Tuple[pd.DataFrame,pd.DataFrame,pd.Index,pd.Index]): Tuple composed of
                    train data, test data, train data timestamps, test timestamps.
        Returns:
            response of the used train algorithm
        """
        train_data, test_data, train_stamps, test_stamps, _ = preprocessed_data
        if self.algorithm is settings.MTAD_GAT:
            #Create SPOT manager
            n_features: int=train_data.shape[1]
            spot_manager=SPOTManager(n_features=n_features,caller=settings.CALLER_TRAIN)

            # Train a detector 
            train_response: tuple[dict[str, list[int]], pd.DataFrame, pd.DataFrame]= train_MTAD_GAT(train_data=train_data,
                                            test_data=test_data,
                                            train_timestamps=train_stamps,
                                            test_timestamps=test_stamps,
                                            config_input=request.get(keys.UC_TRAIN_CONFIG),
                                            test_labels=None)
            # save spot trained object
            spot_manager.save_all_train()
            # destroy the singleton objects
            SPOTManager.destroy_instance()
        else:
            train_response={},pd.DataFrame([]),pd.DataFrame([])
        return train_response


    def predict(self,preprocessed_data) -> None | Tuple[pd.DataFrame,pd.DataFrame]:
        """
        Runs the anomaly detection of the detector using the algorithm self.algorithm
        Args:
            preprocessed_data  (Tuple[pd.DataFrame,pd.DataFrame,pd.Index,pd.Index]): Tuple composed of
                    train data, test data, train data timestamps, test timestamps.
                    For prediction, we assume the split to be zero, hence all data to be encoded as "train_data"
        Returns:
           None | Tuple[pd.DataFrame,pd.DataFrame]: either None or the data frame containing the output of the detection 
                    for every point and those containing only those flagged as anomalies
        """
        data, _, stamps, _, _ = preprocessed_data

        if self.algorithm is settings.MTAD_GAT:      
            # Predict anomalies 
            pred_result = predict_MTAD_GAT(data, stamps) 
            # Check if result is None 
            if pred_result is None:
                raise EscapeError("predict_MTAD_GAT returned None.",logger)         
        return pred_result
        
    def __ship_to_wazuh_training_pipeline(self,column_names,train_out_df,test_out_df,ship_train=False,ship_test=False) -> str:
        """
        Creates a detector stream. And possibly ships train and test data.

        Args:
            column_names (list): A list of column names that specify features. 
            train_out_df (pd.DataFrame):  The DataFrame containing the model's predictions for the training data.
            test_out_df (pd.DataFrame): The DataFrame containing the model's predictions for the test data.

            ship_train (bool, optional): If True, the training data's detection output will be shipped to the Wazuh pipeline. 
                                        Defaults to False.
            ship_test (bool, optional): If True, the test data's detection output will be shipped to the Wazuh pipeline. 
                                        Defaults to False.

        Returns:
            str: detector stream's name
        """
        # retrieve info
        dsm=DataStorageManager()
        # get outcome key names associated to features
        tr,feat_keys=request_handler.shipping_train_data_request(dataframe=train_out_df,column_names=column_names,algorithm=self.algorithm)
        te,_=request_handler.shipping_train_data_request(dataframe=test_out_df,column_names=column_names,algorithm=self.algorithm)
        n_extra: int=len(feat_keys)

        #start data shipper
        wds=WazuhDataShipper()
        # create detector stream  (assuming feature values to be floats)
        _, detector_stream=wds.create_detector_stream(detector_id=dsm.uuid,algorithm=self.algorithm,features=zip(feat_keys,n_extra*["float"]))
        #EscapeInfo(resp,logger)
        #add training docs
        if ship_train:
            re_tr: str=wds.get_bulk_request(tr,detector_stream=detector_stream,actions=len(tr)*[CREATE])
            wds.ship_bulk(re_tr)
        if ship_test:
            EscapeInfo("Add test points to data stream",logger)
            re_te: str=wds.get_bulk_request(te,detector_stream=detector_stream,actions=len(te)*[CREATE])
            wds.ship_bulk(re_te)

        dsm.update_detector_input_parameters_after_training({DETECTOR_STREAM:detector_stream})
        return detector_stream


    def __ship_to_wazuh_prediction_pipeline(self,data:dict,detector_stream) -> None:
        """
        Ships the outcome of prediction to the corresponding detectors stream
        Args:
            data (dictionary): prediction response
            detector_stream (str): detector stream's name associated to the detector used for training
        """
        wds=WazuhDataShipper()
        results:list=data.get(RESP_RESULTS,[])
        bulk_re: str=wds.get_bulk_request(results,detector_stream=detector_stream,actions=len(results)*[CREATE])
        resp_ship=wds.ship_bulk(bulk_re)
        #EscapeInfo(resp_ship)
        

    def destroy_all_singletons(self):
        if self.algorithm is settings.MTAD_GAT: SPOTManager.destroy_instance()
        DataStorageManager.destroy_instance()
        DataRetrievalManager.destroy_instance()