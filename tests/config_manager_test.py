import json
import unittest

from siem_mtad_gat import settings
import siem_mtad_gat.config_manager.config_keys as keys
from siem_mtad_gat.config_manager.config_manager import DetectorConfigManager
from siem_mtad_gat.time_manager import TimeManager



class TestConfigManager(unittest.TestCase):

    def test_no_uc(self):
        dcm=DetectorConfigManager(default_detector_id="")
        train_config=dcm.get_train_config_from_uc_yaml()
        predict_config=dcm.get_predict_config_from_uc_yaml()

        with open(settings.DEFAULT_DETECTOR_INPUT_CONFIG, 'r') as f:
            default_config:dict = json.load(f)
        
        default_config[keys.UC_INDEX_DATE]=TimeManager.get_index_current_month()
                
        default_config[keys.UC_DISPLAY_NAME]= dcm.get_default_detector_name()

        self.assertEqual(train_config,{k:default_config[k] for k in keys.UC_TRAINING_LIST})
        self.assertIsNone(predict_config)

        

    def test_uc_1_t(self):
        dcm=DetectorConfigManager(default_detector_id="",use_case_number=1)
        self.assertEqual(dcm.yaml_file, settings.UC_YAML_FILE.format(number=1))
        self.assertIsNotNone(dcm.uc_n)
        # point to test uc
        dcm.yaml_file=settings.TEST_UC_YAML.format(number=1)
        train_config=dcm.get_train_config_from_uc_yaml()
        predict_config=dcm.get_predict_config_from_uc_yaml()
        self.assertIsNone(train_config)
        self.assertEqual(predict_config,{keys.UC_BATCH_SIZE: 3, keys.UC_RUN_MODE : settings.RUN_MODE.BATCH, keys.UC_DETECTOR_ID: ""})

    def test_uc_2_t(self):
        n=2
        dcm=DetectorConfigManager(default_detector_id="",use_case_number=n)
        self.assertEqual(dcm.yaml_file, settings.UC_YAML_FILE.format(number=n))
        self.assertIsNotNone(dcm.uc_n)
        # point to test uc
        dcm.yaml_file=settings.TEST_UC_YAML.format(number=n)
        train_config=dcm.get_train_config_from_uc_yaml()
        predict_config=dcm.get_predict_config_from_uc_yaml()
        dt=train_config.get(keys.UC_TRAIN_CONFIG)
        d0={keys.UC_WINDOW_SIZE: 6, keys.UC_EPOCHS : 2}
        self.assertEqual(d0,dt)
        self.assertIsNone(predict_config)
        self.assertEqual(train_config.get(keys.UC_AGGREGATION_CONFIG),{})

    def test_uc_3_t(self):
        n=3
        dcm=DetectorConfigManager(default_detector_id="",use_case_number=n)
        self.assertEqual(dcm.yaml_file, settings.UC_YAML_FILE.format(number=n))
        dcm.yaml_file=settings.TEST_UC_YAML.format(number=n)
        self.assertIsNotNone(dcm.uc_n)
        dcm_df=DetectorConfigManager("")
        tc=dcm.get_train_config_from_uc_yaml()
        tc1=dcm_df.get_train_config_from_uc_yaml()
        self.assertEqual(tc,tc1)
        cp=dcm.get_predict_config_from_uc_yaml()
        cp1=dcm_df.get_predict_config_from_uc_yaml()
        self.assertEqual(cp,cp1)

    def test_uc_4_t(self):
        n=4
        dcm=DetectorConfigManager(default_detector_id="",use_case_number=n)
        self.assertEqual(dcm.yaml_file, settings.UC_YAML_FILE.format(number=n))
        self.assertIsNotNone(dcm.uc_n)
        dcm.yaml_file=settings.TEST_UC_YAML.format(number=n)
        self.assertIsNone(dcm.get_train_config_from_uc_yaml())
        predict_config=dcm.get_predict_config_from_uc_yaml()
        self.assertEqual(predict_config.get(keys.UC_DETECTOR_ID),"7f240591-3b5b-4cc8-91fe-09ce51f7ff85")
        self.assertEqual(predict_config.get(keys.UC_RUN_MODE),settings.RUN_MODE.HISTORICAL)
        self.assertEqual(predict_config.get(keys.UC_START_TIME),"2023-11-01T12:24:33Z")
        
        

    def test_default_behaviour(self):
        # if initialised with None, the detector config manager returnes default training configuration! This is independent of the default detector ID.
        # for prediction default behaviour is retur None
        n=3
        dcm=DetectorConfigManager(default_detector_id="",use_case_number=n)
        self.assertEqual(dcm.yaml_file, settings.UC_YAML_FILE.format(number=n))
        self.assertIsNotNone(dcm.uc_n)
        dcm_df=DetectorConfigManager(None)
        dcm.yaml_file=settings.TEST_UC_YAML.format(number=n)
        self.assertEqual(dcm.get_train_config_from_uc_yaml(),dcm_df.get_train_config_from_uc_yaml())
        self.assertIsNone(dcm.get_predict_config_from_uc_yaml())
        self.assertEqual(dcm.get_predict_config_from_uc_yaml(),dcm_df.get_predict_config_from_uc_yaml())

