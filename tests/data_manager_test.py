import os
import unittest

from unittest.mock import patch

import pandas as pd

from siem_mtad_gat import settings
from siem_mtad_gat.commons import EscapeError
from siem_mtad_gat.data_manager.data_retrieval_manager import DataRetrievalManager
from siem_mtad_gat.data_manager.data_storage_manager import DataStorageManager
from siem_mtad_gat.data_manager.detectors import retrieve_all_detector_ids
from siem_mtad_gat.mtad_gat_pytorch.spot import SPOT
from tests.utils import KEEP_ASSETS, file_exists, rm_detector_folder



class TestManagersSetUp(unittest.TestCase):
    def setUp(self):
        data_storage_manager = DataStorageManager('2d36a80a-c47a-4eb4-bb3e-5b2bfb90dc95')
        data_retrieval_manager = DataRetrievalManager(data_storage_manager.uuid)   

    def test1(self):  
        dsm = DataStorageManager()
        self.assertEqual(dsm.uuid,'2d36a80a-c47a-4eb4-bb3e-5b2bfb90dc95')

    def test2(self):  
        drm = DataRetrievalManager()
        self.assertEqual(drm.detector_id,'2d36a80a-c47a-4eb4-bb3e-5b2bfb90dc95')   

    def tearDown(self):
        rm_detector_folder() 
        DataStorageManager.destroy_instance()
        DataRetrievalManager.destroy_instance()


class TestStorageMethods(unittest.TestCase):
    def setUp(self):
        self.dsm = DataStorageManager()

    def test_save_detector_input_parameters(self):
        dsm: DataStorageManager=self.dsm
        uid=dsm.uuid
        directory=settings.DETECTOR_FOLDER.format(id=uid)
        filename=settings.DETECTOR_INPUT_PARAMETERS_FILE_PATH.format(id=uid)
        self.assertFalse(file_exists(directory, filename))
        dsm.save_detector_input_parameters({'mock':'input'})
        self.assertTrue(file_exists(directory, filename))

    def test_save_input_data(self):
        dsm=self.dsm
        xx = {'c1': [1, 2], 'c2': [3, 4]}
        df = pd.DataFrame(data=xx)
        self.assertFalse(os.path.exists(settings.INPUT_STORAGE_FOLDER.format(id=dsm.uuid)))
        self.assertFalse(os.path.exists(settings.PREDICTION_STORAGE_FOLDER.format(id=dsm.uuid)))
        
        # test save input train
        dsm.save_input_data(df,caller=settings.CALLER_TRAIN)
        self.assertTrue(os.path.exists(settings.INPUT_STORAGE_FOLDER.format(id=dsm.uuid)))
        self.assertFalse(os.path.exists(settings.INPUT_DATA_PKL_FILE_PATH.format(id=dsm.uuid)))
        dsm.save_input_data(df,caller=settings.CALLER_TRAIN,save_pickle=True,save_csv=True)
        self.assertTrue(os.path.exists(settings.INPUT_DATA_PKL_FILE_PATH.format(id=dsm.uuid)))
        self.assertTrue(os.path.exists(settings.INPUT_DATA_CSV_FILE_PATH.format(id=dsm.uuid)))
        # test save input predict
        dsm.save_input_data(df,caller=settings.CALLER_PREDIC)
        self.assertTrue(os.path.exists(settings.PREDICTION_STORAGE_FOLDER.format(id=dsm.uuid)))
        self.assertFalse(os.path.exists(settings.PREDICTION_DATA_PKL_FILE_PATH.format(id=dsm.uuid)))
        dsm.save_input_data(df,caller=settings.CALLER_PREDIC,save_pickle=True,save_csv=True)
        self.assertTrue(os.path.exists(settings.PREDICTION_DATA_PKL_FILE_PATH.format(id=dsm.uuid)))
        self.assertTrue(os.path.exists(settings.PREDICTION_DATA_CSV_FILE_PATH.format(id=dsm.uuid)))

    def test_save_predict_output(self):
        pass

    def test_save_train_logs(self):
        pass

    def test_save_model(self):
        pass

    def test_save_summary(self):
        pass   

    def test_save_training_outputs(self):
        dsm=self.dsm
        xx = {'c1': [1, 2], 'c2': [3, 4]}
        df = pd.DataFrame(data=xx)
        self.assertFalse(os.path.exists(settings.TRAINING_STORAGE_FOLDER.format(id=dsm.uuid)))
        dsm.save_training_outputs(df,df)
        self.assertTrue(os.path.exists(settings.TRAIN_OUTPUT_PKL_FILE_PATH.format(id=dsm.uuid)))
        self.assertTrue(os.path.exists(settings.TEST_OUTPUT_PKL_FILE_PATH.format(id=dsm.uuid)))
        
        with self.assertRaises(Exception):
            dsm.save_training_outputs("uu",df)


    def test_save_training_config(self):
        pass
    
    
    def test_save_losses(self):
        pass   

    def test_save_yaml_predict(self):
        pass   

    def test_save_yaml_train(self):
        pass   
   
    def test_save_spot_train(self):
                
        dsm=self.dsm
        self.assertFalse(os.path.exists(settings.SPOT_TRAIN_STORAGE_FOLDER.format(id=dsm.uuid)))
        spot=SPOT()

        # numerical feature pkl
        dsm.save_spot(spot,1)
        self.assertTrue(os.path.exists(settings.SPOT_TRAIN_FILE_PATH.format(id=dsm.uuid,feature=1,ext="pkl")))
        self.assertFalse(os.path.exists(settings.SPOT_TRAIN_FILE_PATH.format(id=dsm.uuid,feature=0,ext="pkl")))
        dsm.save_spot(spot,1,file_ext='json')
        #json
        self.assertTrue(os.path.exists(settings.SPOT_TRAIN_FILE_PATH.format(id=dsm.uuid,feature=1,ext='json')))
        self.assertFalse(os.path.exists(settings.SPOT_TRAIN_FILE_PATH.format(id=dsm.uuid,feature=0,ext='json')))


        #global
        dsm.save_spot(spot,-1)
        self.assertTrue(os.path.exists(settings.SPOT_TRAIN_FILE_PATH.format(id=dsm.uuid,feature="global",ext="pkl")))
        
    def test_save_preprocessing_scaler(self):
        dsm=self.dsm
        dsm.save_preprocessing_scaler("")
        self.assertTrue(os.path.exists(settings.SCALER_FILE_PATH.format(id=dsm.uuid,feature=1,ext='json')))
        
    def tearDown(self):
        if not KEEP_ASSETS: rm_detector_folder()
        DataStorageManager.destroy_instance()
        
class TestRetrieval(unittest.TestCase):
    def setUp(self):
        dsm = DataStorageManager('2d36a80a-c47a-4eb4-bb3e-5b2bfb90dc95')
        drm = DataRetrievalManager(dsm.uuid)       

    def test_all_methods_with_no_input(self):
        drm=DataRetrievalManager() # type: ignore
        drm.model_path()
        drm.retrieve_detector_parameters()
        drm.retrieve_predict_output()
        with self.assertRaises(EscapeError):
            drm.retrieve_summary()
        drm.retrieve_training_config()
        drm.retrieve_training_outputs()
        drm.load_preprocessing_scaler()
    
    def tearDown(self):
        if not KEEP_ASSETS: rm_detector_folder()
        DataStorageManager.destroy_instance()