import os
import unittest
from unittest.mock import MagicMock, call, create_autospec, patch

from siem_mtad_gat.ad_driver.driver import main
from siem_mtad_gat.ad_engine.mtad_gat.ad_engine import ADEngine
from siem_mtad_gat.shipper.wazuh_data_shipper import WazuhDataShipper


class TestDriver(unittest.TestCase):
    
    @patch('sys.argv', ["main",'-s'])
    def test_s(self):
        with patch('siem_mtad_gat.ad_driver.driver.WazuhDataShipper') as MockWDS:
            with self.assertRaises(SystemExit): 
                main()
            MockWDS.assert_called_once_with(install=True)
            self.assertTrue('call().add_rollover_policy()' in [str(c) for c in MockWDS.mock_calls])
                    
    @patch('sys.argv', ["main",'-u','11'])
    def test_u(self):
        with patch('siem_mtad_gat.ad_driver.driver.ADEngine', spec=True) as MockEngine:
            MockEngine.return_value.get_training_requests_from_uc.return_value={"mock_train"}
            MockEngine.return_value.get_prediction_requests_from_uc.return_value={"mock_pred"}
            lc=['get_training_requests_from_uc(uc_number=11)',"training_pipeline(training_request={'mock_train'})",
                'get_prediction_requests_from_uc(uc_number=11)',"run_prediction_pipeline(prediction_request={'mock_pred'}, uc_number=11)"]
            with self.assertRaises(SystemExit): 
                main()
            MockEngine.assert_called_once()
            expected_calls=map(lambda x:'call().'+x,lc)
            calls= [str(c) for c in MockEngine.mock_calls]
            for call in expected_calls:
                self.assertTrue(call in calls)


    @patch('sys.argv', ["main",'-u','8','-s'])
    def test_u_s(self):
        with patch('siem_mtad_gat.ad_driver.driver.WazuhDataShipper') as MockWDS:
            with patch('siem_mtad_gat.ad_driver.driver.ADEngine', spec=True) as MockEngine:
                MockEngine.return_value.get_training_requests_from_uc.return_value={"mock_train"}
                MockEngine.return_value.get_prediction_requests_from_uc.return_value={"mock_pred"}                
                with self.assertRaises(SystemExit): 
                    main()
                MockWDS.assert_called_once_with(install=False)
                self.assertFalse('call().add_rollover_policy()' in [str(c) for c in MockWDS.mock_calls])

                lc=['get_training_requests_from_uc(uc_number=8)',"training_pipeline(training_request={'mock_train'})",
                    'get_prediction_requests_from_uc(uc_number=8)',"run_prediction_pipeline(prediction_request={'mock_pred'}, uc_number=8)"]
                MockEngine.assert_called_once()
                expected_calls=map(lambda x:'call().'+x,lc)
                calls= [str(c) for c in MockEngine.mock_calls]
                for call in expected_calls:
                    self.assertTrue(call in calls)


    @patch('sys.argv', ["main",'-i'])
    def test_i(self):
        with patch('siem_mtad_gat.ad_driver.driver.Console') as mock_console:
            main()
            mock_console.assert_called_once_with(False)

    @patch('sys.argv', ["main",'-i','-s'])
    def test_i_s(self):
        with patch('siem_mtad_gat.ad_driver.driver.Console') as mock_console:
            main()
            mock_console.assert_called_once_with(True)

    @patch('sys.argv', ["main",'-c'])
    def test_c(self):
        with patch('siem_mtad_gat.ad_driver.driver.WazuhDataIngestor') as MockWDI:
            with self.assertRaises(SystemExit): 
                main()
            MockWDI.assert_called_once()
            self.assertTrue('call().check_connection()' in [str(c) for c in MockWDI.mock_calls])
                