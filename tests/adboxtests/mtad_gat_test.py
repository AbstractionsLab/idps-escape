import pickle
import unittest

import numpy as np
import pandas as pd

from adbox import settings
from adbox.data_manager.data_retrieval_manager import DataRetrievalManager
from adbox.data_manager.data_storage_manager import DataStorageManager
from adbox.data_manager.spot_manager import SPOTManager
from adbox.data_transformer import DataPreprocessor
from adbox.mtad_gat_pytorch.predict_alab import predict_MTAD_GAT
from adbox.mtad_gat_pytorch.train_alab import train_MTAD_GAT
import adbox.mtad_gat_pytorch.mtad_gat_keys as keys
from .utils import rm_detector_folder


class TestAssumptions(unittest.TestCase):

    def test_assumption(self):
        df = pd.DataFrame(data={'c1': [1, 2], 'c2': [3, 4]})
        ts = [0,1]
        self.assertEqual(DataStorageManager._instance,None)
        with self.assertRaises(Exception):
                train_MTAD_GAT(df,df,ts,ts,{})
                self.assertEqual(SPOTManager._instance,None)
        with self.assertRaises(Exception):
                train_MTAD_GAT(df,df,ts,ts,{})

    def tearDown(self):
            rm_detector_folder() 
            DataStorageManager.destroy_instance()
            DataRetrievalManager.destroy_instance()
            self.assertEqual(DataStorageManager._instance,None)
            self.assertEqual(DataRetrievalManager._instance,None)
            self.assertEqual(SPOTManager._instance,None)       

class TestTrain(unittest.TestCase):
    def setUp(self) -> None:
        self.data_storage_manager = DataStorageManager('-test-train_MTAD_GAT-')
        data_retrieval_manager = DataRetrievalManager(self.data_storage_manager.uuid)     
        self.input_path=settings.INPUT_DATA_PKL_FILE_PATH.format(id='7f240591-3b5b-4cc8-91fe-09ce51f7ff85')
        spot_manager=SPOTManager(n_features=3)
        self.train_config={
                keys.MTAD_GAT_EPOCHS: 2,
                keys.MTAD_GAT_WINDOW_SIZE: 6
            }


    def test_missing_input(self):
        with self.assertRaises(ValueError) as ex:
            train_MTAD_GAT(None, np.array([1,1,2,3]), pd.Index([]),pd.Index([]),self.train_config,test_labels=None)

    def test_input(self):
            with open(self.input_path, "rb") as f:
                        input_data=pickle.load(f)
            # Preprocessing
            train_data, test_data = DataPreprocessor.split_data(input_data, 0.3)
            train_stamps = train_data.index
            test_stamps = test_data.index
            column_names = train_data.columns
            train_data,train_scaler=DataPreprocessor.normalize_data(train_data,None)
            if test_data.shape[0]!=0 : test_data,_=DataPreprocessor.normalize_data(test_data,train_scaler)
            self.data_storage_manager.save_preprocessing_scaler(train_scaler)
            
            # Train a detector 
            train_response,_,_ = train_MTAD_GAT(train_data, 
                                            test_data, 
                                            train_stamps, 
                                            test_stamps, 
                                            self.train_config, 
                                            test_labels=None) 
            self.assertEqual(len(train_response.get(keys.MTAD_GAT_OUT_EPOCHS_IDS,[])),2)
 

    def tearDown(self):
            rm_detector_folder()
            SPOTManager.destroy_instance() 
            DataStorageManager.destroy_instance()
            DataRetrievalManager.destroy_instance()
            self.assertEqual(DataStorageManager._instance,None)
            self.assertEqual(DataRetrievalManager._instance,None)
            self.assertEqual(SPOTManager._instance,None)                    



class TestPredict(unittest.TestCase):
    def setUp(self) -> None:
        self.data_storage_manager = DataStorageManager('7f240591-3b5b-4cc8-91fe-09ce51f7ff85')
        drm = DataRetrievalManager(self.data_storage_manager.uuid)     
        self.input_path=settings.PREDICTION_DATA_PKL_FILE_PATH .format(id=self.data_storage_manager.uuid) 
        # retrieve training configuration
        self.config = drm.retrieve_training_config()
        spot_manager=SPOTManager(n_features=3,load_obj=True,caller=settings.CALLER_OFFLINE)
    

    def test(self):
            with open(self.input_path, "rb") as f:
                        input_data=pickle.load(f)
            # Preprocessing
            data, _ = DataPreprocessor.split_data(input_data, split=0)
            stamps = data.index
            data_retrieval_manager=DataRetrievalManager()
            scaler=data_retrieval_manager.load_preprocessing_scaler()
            data,scaler=DataPreprocessor.normalize_data(data,scaler)
            
            ws:int=self.config.get(keys.MTAD_GAT_WINDOW_SIZE,0)
            self.assertNotEqual(ws,0)



            sp=SPOTManager()
            self.assertIsNotNone(sp.spot_list[0].Nt)

            df, anomalies = predict_MTAD_GAT(data,stamps)
            self.assertIsNotNone(df)
            self.assertEqual(df.shape,(len(stamps)-ws,21))# 4x3 + 1 +2x(3+1)

    def tearDown(self):
            rm_detector_folder()
            SPOTManager.destroy_instance() 
            DataStorageManager.destroy_instance()
            DataRetrievalManager.destroy_instance()
            self.assertEqual(DataStorageManager._instance,None)
            self.assertEqual(DataRetrievalManager._instance,None)
            self.assertEqual(SPOTManager._instance,None)   