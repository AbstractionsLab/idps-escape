import unittest

import pandas as pd
import siem_mtad_gat.settings as settings
from siem_mtad_gat.request_response_handler.response_handler import *

LIST=[RESP_RESULTS,RESP_RUN_MODE,RESP_DETECTOR_ID,RESP_START_TIME,RESP_END_TIME,confkeys.UC_BATCH_SIZE]


class TestPredictionBlocks(unittest.TestCase):
    def testAlgorithm(self):
        request: dict = {
                RESP_RUN_MODE: settings.RUN_MODE.BATCH,
                RESP_DETECTOR_ID: "id",
                RESP_START_TIME: "0",
                RESP_END_TIME: "1",
                RESP_RESULTS: []
        }   
        with self.assertRaises(EscapeError):
            prediction_pipeline_response(request,dataframe=pd.DataFrame([]),out_interval_extrema=('a','b'),algorithm=None,column_names=[])


class TestFunctions(unittest.TestCase):
    def test_prediction_pipeline_response_MTAD_GAT(self):
        request: dict = {
                RESP_RUN_MODE: settings.RUN_MODE.BATCH,
                RESP_DETECTOR_ID: "id",
                RESP_START_TIME: "0",
                RESP_END_TIME: "1",
                confkeys.UC_BATCH_SIZE: "3",
                RESP_RESULTS: []
        }   
        df=pd.DataFrame(data={'c1': [1, 2], 'c2': [3, 4],'time':[pd.Timestamp('2024-07-01T00:03:26Z'),pd.Timestamp('2024-07-01T00:03:26Z')]})
        df.set_index('time',inplace=True)
        re= prediction_pipeline_response(request,dataframe=df,out_interval_extrema=('a','b'),algorithm=settings.MTAD_GAT,column_names=['col1','col2'])
        al=all([(k in LIST) and (isinstance(v,str) or isinstance(v,list)) for k,v in re.items()])
        self.assertTrue(al)