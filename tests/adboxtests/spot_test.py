import unittest
import adbox.settings as settings

from adbox.commons import EscapeError
from adbox.data_manager.data_retrieval_manager import DataRetrievalManager
from adbox.data_manager.data_storage_manager import DataStorageManager
from adbox.data_manager.spot_manager import SPOTManager
from .utils import rm_detector_folder



class TestSPOT(unittest.TestCase):
    def setUp(self):
        data_storage_manager = DataStorageManager()
        id=data_storage_manager.uuid
        data_retrieval_manager = DataRetrievalManager(id)     
        

    def test_list_len(self):
        n=3
        spot_manager=SPOTManager(n_features=n)
        l=len(spot_manager.spot_list) # type: ignore
        self.assertEqual(l, n+1, f"SPOT list length is {l} while it should be {n}")

    def test_proba(self):
        n=1
        q=0.1
        spot_manager=SPOTManager(n_features=n,q=q)
        qi=spot_manager.spot_list[0].proba # type: ignore
        self.assertEqual(q, qi, f"SPOT q is {qi} while it should be {q}")


    def test_save_all(self):
        n=2
        spot_manager=SPOTManager(n_features=n,load_obj=False)
        spot_manager.save_all_train()        

    def test_empty_input(self):
        with self.assertRaises(EscapeError) as ex:
            spot_manager=SPOTManager() # type: ignore
               

    def tearDown(self):
        SPOTManager.destroy_instance()
        rm_detector_folder() 
        DataStorageManager.destroy_instance()
        DataRetrievalManager.destroy_instance()
        

class TestSPOTAssumptions(unittest.TestCase):  
    def test_call(self):
        with self.assertRaises(EscapeError):
            SPOTManager()  # type: ignore


    def test_DataM(self):
        n=2
        self.assertEqual(DataStorageManager._instance,None)
        with self.assertRaises(TypeError):
            spot_manager=SPOTManager(n_feature=n)

    def tearDown(self):
        SPOTManager.destroy_instance()        


class TestSPOT_load(unittest.TestCase):
    def setUp(self):
        data_storage_manager = DataStorageManager('2d36a80a-c47a-4eb4-bb3e-5b2bfb90dc95')
        id=data_storage_manager.uuid
        data_retrieval_manager = DataRetrievalManager(id)     
    
    def test_load_true(self):
        n=2
        spot_manager=SPOTManager(n_features=n,load_obj=True,caller=settings.CALLER_OFFLINE)

    def test_load_false(self):
        n=2
        spot_manager=SPOTManager(n_features=n,load_obj=False)

    def tearDown(self):
            SPOTManager.destroy_instance()
            rm_detector_folder() 
            DataStorageManager.destroy_instance()
            DataRetrievalManager.destroy_instance()    


if __name__ == '__main__':
    unittest.main()