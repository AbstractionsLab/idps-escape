import os
import unittest
from unittest.mock import patch

import numpy as np
import pandas as pd

from siem_mtad_gat.ad_engine.mtad_gat.ad_engine import ADEngine
from siem_mtad_gat.commons import EscapeError
from siem_mtad_gat.data_manager.data_retrieval_manager import DataRetrievalManager
from siem_mtad_gat.data_manager.data_storage_manager import DataStorageManager
from siem_mtad_gat.data_manager.spot_manager import SPOTManager
from .utils import rm_detector_folder_from_id
import siem_mtad_gat.settings as settings
import siem_mtad_gat.config_manager.config_keys as keys

class TestEngineAssumptions(unittest.TestCase):
    def test_predict_no_detectors(self):
        uc=1
        # if the list of detectors is empty the engine should raise and error if predict pipeline is started
        engine=ADEngine()
        engine.detectors=[]
        engine.current_detector_id=None
        engine.test_env=True
        self.assertEqual(engine.detectors,[])
        pred_request=engine.get_prediction_requests_from_uc(uc_number=uc)
        r=engine.prediction_pipeline(prediction_request=pred_request,uc_number=uc)
        with self.assertRaises(EscapeError):  next(r)



    def test_predict_no_input_config(self):
        engine=ADEngine()
        predict_response = engine.prediction_pipeline(prediction_request=None,uc_number=0)
        with self.assertRaises(StopIteration):  next(predict_response)


    def tearDown(self) -> None:
        self.assertEqual(DataStorageManager._instance,None)
        self.assertEqual(DataRetrievalManager._instance,None)
        self.assertEqual(SPOTManager._instance,None)

class TestEngineTraining(unittest.TestCase):
    @patch('siem_mtad_gat.ad_engine.mtad_gat.ad_engine.ADEngine.train')
    @patch('siem_mtad_gat.ad_engine.mtad_gat.ad_engine.ADEngine.transform')
    def test_uc_2_t(self,mock_transform,mock_train):
        n=2
        engine=ADEngine()
        engine.test_env=True
        mock_train.return_value={},pd.DataFrame([]),pd.DataFrame([])
        mock_transform.return_value=np.array([]),None,None,None,[]
        train_request=engine.get_training_requests_from_uc(uc_number=n)
        pred_request=engine.get_prediction_requests_from_uc(uc_number=n)
        response_train=engine.training_pipeline(training_request=train_request)
        response_predict=engine.prediction_pipeline(prediction_request=pred_request,uc_number=n)
        with self.assertRaises(StopIteration): next(response_predict)
        id=response_train.get(keys.UC_DETECTOR_ID,"")
        rm_detector_folder_from_id(id)

    def tearDown(self) -> None:
        self.assertEqual(DataStorageManager._instance,None)
        self.assertEqual(DataRetrievalManager._instance,None)
        self.assertEqual(SPOTManager._instance,None)

class TestEngineFullRun(unittest.TestCase):    
    def test_uc_5_t_run_full(self):
        n=5
        engine=ADEngine()
        engine.test_env=True
        train_request=engine.get_training_requests_from_uc(uc_number=n)
        ## train
        response_train=engine.training_pipeline(training_request=train_request)
        id=response_train.get(keys.UC_DETECTOR_ID)
        # List of expect output of training pipeline
        exp_out=[settings.DETECTOR_INPUT_PARAMETERS_FILE_PATH,settings.TRAINING_LOSSES_IMAGE_PATH,settings.TRAIN_DATA_FOLDER,settings.SPOT_TRAIN_STORAGE_FOLDER,settings.TRAINING_LOSSES_FILE_PATH,settings.TRAIN_OUTPUT_PKL_FILE_PATH,settings.TEST_OUTPUT_PKL_FILE_PATH,settings.MODEL_FILE_PATH,settings.SCALER_FILE_PATH]
        out_iter=map(lambda x:x.format(id=id),exp_out)
        # checks if all the files/directory exist
        for file in out_iter: self.assertTrue(os.path.exists(file))    

        #predict
        pred_request=engine.get_prediction_requests_from_uc(uc_number=n)
        response_predict=engine.prediction_pipeline(prediction_request=pred_request,uc_number=n)
        with self.assertRaises(StopIteration): next(response_predict)
        rm_detector_folder_from_id(id)
    def tearDown(self) -> None:
        self.assertEqual(DataStorageManager._instance,None)
        self.assertEqual(DataRetrievalManager._instance,None)
        self.assertEqual(SPOTManager._instance,None)        

class TestEngineHistorical(unittest.TestCase):
    @patch('siem_mtad_gat.ad_engine.mtad_gat.ad_engine.ADEngine.ingest_prediction')
    @patch('siem_mtad_gat.ad_engine.mtad_gat.ad_engine.ADEngine.transform')
    @patch('siem_mtad_gat.ad_engine.mtad_gat.ad_engine.ADEngine.predict')
    def test_uc_4_t(self, mock_predict,mock_transform,mock_ingest):
        #mocking pipeline
        transformed_data=np.array([]),None,None,None,[]
        mock_transform.return_value=transformed_data
        ingested_data=[]
        mock_ingest.return_value=ingested_data
        mock_predict.return_value=pd.DataFrame([]),pd.DataFrame([])
        n=4
        engine=ADEngine()
        engine.test_env=True
        
        #expected training pipeline not running and returning None
        train_request=engine.get_training_requests_from_uc(uc_number=n)
        response_train=engine.training_pipeline(training_request=train_request)
        self.assertIsNone(response_train)
        mock_ingest.assert_not_called()  
        mock_predict.assert_not_called()  
        mock_transform.assert_not_called()  

        pred_request=engine.get_prediction_requests_from_uc(uc_number=n)
        response_predict=engine.prediction_pipeline(prediction_request=pred_request,uc_number=n)
        first = next(response_predict)
        self.assertEqual(first.get(keys.UC_RUN_MODE),settings.RUN_MODE.HISTORICAL.name)
        self.assertEqual(first.get(keys.UC_START_TIME),"2023-11-01T12:27:30Z") # shift of one window the fetching start time
        self.assertEqual(first.get(keys.UC_END_TIME),"2023-11-01T20:00:30Z") #roundef
        with self.assertRaises(StopIteration): next(response_predict)
        mock_ingest.assert_called_with(request=pred_request,start_time="2023-11-01T12:24:30Z",end_time="2023-11-01T20:00:30Z")  
        mock_transform.assert_called_with(pred_request,ingested_data,caller=settings.CALLER_PREDIC)
        mock_predict.assert_called_with(transformed_data)
        

    def tearDown(self) -> None:
        self.assertEqual(DataStorageManager._instance,None)
        self.assertEqual(DataRetrievalManager._instance,None)
        self.assertEqual(SPOTManager._instance,None)    

class TestEngineTrainHistorical(unittest.TestCase):
    @patch('siem_mtad_gat.data_manager.spot_manager.SPOTManager._load_all')
    @patch('siem_mtad_gat.ad_engine.mtad_gat.ad_engine.ADEngine.ingest_prediction')
    @patch('siem_mtad_gat.ad_engine.mtad_gat.ad_engine.ADEngine.ingest_training')
    @patch('siem_mtad_gat.ad_engine.mtad_gat.ad_engine.ADEngine.transform')
    @patch('siem_mtad_gat.ad_engine.mtad_gat.ad_engine.ADEngine.predict')
    @patch('siem_mtad_gat.ad_engine.mtad_gat.ad_engine.ADEngine.train')
    def test_uc_6_t(self,mock_train, mock_predict,mock_transform,mock_ingest_train,mock_ingest_prediction,mock_spot):
        #mocking pipeline
        transformed_data=np.array([]),None,None,None,[]
        mock_transform.return_value=transformed_data
        mock_train.return_value={},pd.DataFrame([]),pd.DataFrame([])
        ingested_data=[]
        mock_ingest_train.return_value=ingested_data,"source"

        n=6
        engine=ADEngine()
        engine.test_env=True
        
        init_id=engine.current_detector_id
        #expected training pipeline not running and returning None
        train_request=engine.get_training_requests_from_uc(uc_number=n)
        response_train=engine.training_pipeline(training_request=train_request)
        
        mock_ingest_train.assert_called()  
        mock_train.assert_called()  
        mock_transform.assert_called()  
        new_id=response_train.get(keys.UC_DETECTOR_ID,"")
        self.assertNotEqual(new_id,init_id)
        self.assertEqual(new_id,engine.current_detector_id)

        mock_ingest_prediction.return_value=ingested_data
        mock_predict.return_value=pd.DataFrame([]),pd.DataFrame([])
        mock_spot.return_value=[]
        pred_request=engine.get_prediction_requests_from_uc(uc_number=n)
        response_predict=engine.prediction_pipeline(prediction_request=pred_request,uc_number=n)
        first = next(response_predict)
        self.assertEqual(first.get(keys.UC_DETECTOR_ID),new_id)
        self.assertEqual(first.get(keys.UC_RUN_MODE),settings.RUN_MODE.HISTORICAL.name)
        self.assertEqual(first.get(keys.UC_START_TIME),"2024-09-01T12:27:00Z") # shift of one window the fetching start time
        self.assertEqual(first.get(keys.UC_END_TIME),"2024-09-01T20:01:00Z") #roundef
        with self.assertRaises(StopIteration): next(response_predict)
        mock_ingest_prediction.assert_called_with(request=pred_request,start_time="2024-09-01T12:24:00Z",end_time="2024-09-01T20:01:00Z")  
        mock_transform.assert_called_with(pred_request,ingested_data,caller=settings.CALLER_PREDIC)
        self.assertEqual(first.get(keys.UC_DETECTOR_ID),new_id)
        mock_predict.assert_called_with(transformed_data)
        rm_detector_folder_from_id(new_id)
    
    def tearDown(self) -> None:
        self.assertEqual(DataStorageManager._instance,None)
        self.assertEqual(DataRetrievalManager._instance,None)
        self.assertEqual(SPOTManager._instance,None)

class TestEngineBatch(unittest.TestCase):
    @patch('threading.Event.wait')
    @patch('siem_mtad_gat.time_manager.TimeManager.now_str')
    @patch('siem_mtad_gat.data_manager.spot_manager.SPOTManager._load_all')
    @patch('siem_mtad_gat.ad_engine.mtad_gat.ad_engine.ADEngine.ingest_prediction')
    @patch('siem_mtad_gat.ad_engine.mtad_gat.ad_engine.ADEngine.transform')
    @patch('siem_mtad_gat.ad_engine.mtad_gat.ad_engine.ADEngine.predict')
    def test_uc_1_t(self,mock_predict,mock_transform,mock_ingest_prediction,mock_spot,mock_now,mock_wait):
        #mocking pipeline
        
        n=1 
        engine=ADEngine()
        engine.test_env=True
        engine.current_detector_id='7f240591-3b5b-4cc8-91fe-09ce51f7ff85'# granularuty 30 s and window_size 6
        ingested_data=[]
        transformed_data=np.array([]),None,None,None,[]
        mock_transform.return_value=transformed_data
        mock_ingest_prediction.return_value=ingested_data
        mock_predict.return_value=pd.DataFrame([]),pd.DataFrame([])
        mock_spot.return_value=[]
        mock_now.return_value='2024-01-01T00:00:03Z'
        mock_wait.return_value=False



        pred_request=engine.get_prediction_requests_from_uc(uc_number=n)
        response_predict=engine.prediction_pipeline(prediction_request=pred_request,uc_number=n)

        first = next(response_predict)
        self.assertEqual(first.get(keys.UC_RUN_MODE),settings.RUN_MODE.BATCH.name)
        self.assertEqual(first.get(keys.UC_BATCH_SIZE),'3') 
        self.assertEqual(first.get(keys.UC_START_TIME),"2023-12-31T23:59:00Z") # shift of one window the fetching start time
        self.assertEqual(first.get(keys.UC_END_TIME),"2024-01-01T00:00:30Z") #roundef
        mock_ingest_prediction.assert_called_with(request=pred_request,start_time="2023-12-31T23:56:00Z",end_time="2024-01-01T00:00:30Z")  
        mock_transform.assert_called_with(pred_request,ingested_data,caller=settings.CALLER_PREDIC)
        mock_predict.assert_called_with(transformed_data)
        second=next(response_predict)
        self.assertEqual(second.get(keys.UC_START_TIME),"2024-01-01T00:00:30Z") # shift of one window the fetching start time
        self.assertEqual(second.get(keys.UC_END_TIME),"2024-01-01T00:02:00Z") #roundef
        mock_ingest_prediction.assert_called_with(request=pred_request,start_time="2023-12-31T23:57:30Z",end_time="2024-01-01T00:02:00Z")
         
        engine.destroy_all_singletons()
    
    def tearDown(self) -> None:
        self.assertEqual(DataStorageManager._instance,None)
        self.assertEqual(DataRetrievalManager._instance,None)
        self.assertEqual(SPOTManager._instance,None)