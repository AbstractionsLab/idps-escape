import pandas as pd
from adbox import settings
from adbox.mtad_gat_pytorch import mtad_gat_keys
from adbox.request_response_handler.keys import *


class BlockPrediction:
    def __init__(self,dataframe:pd.DataFrame,mapping:dict={}):
        self.df: pd.DataFrame=dataframe
        self.mapping=mapping

        rename_feat_map,self.feat_keys=self.__rename_feat_cols_map()
        self.df=self.df.rename(columns=rename_feat_map)
        
        
    def get_prediction_block(self,alg:str):
        map = {
        settings.MTAD_GAT : self.__MTAD_GAT,
        None : None   
        }    
        return map.get(alg)

    def __MTAD_GAT(self):
        results = []
        for index, row in self.df.iterrows():
            # Extracting values for A_Pred_Global and A_Score_Global from the current row
            is_anomaly = bool(row.get(mtad_gat_keys.MTAD_GAT_OUT_PREDICTION_GLOBAL))
            score = row.get(mtad_gat_keys.MTAD_GAT_OUT_SCORE_GLOBAL)
            threshold = row.get(mtad_gat_keys.MTAD_GAT_OUT_THRESHOLD_GLOBAL)
            prediction_values={key:row.get(key) for key in self.feat_keys}
            
            timestamp = index.strftime(settings.DATE_TIME_FORMAT) # type: ignore
            result_entry = {
                    TIMESTAMP: timestamp,
                    IS_ANOMALY: is_anomaly,
                    SCORE: score,
                    THRESHOLD: threshold,
                    } 
            result_entry.update(prediction_values) 
            results.append(result_entry)   
        return results

        
    def __rename_feat_cols_map(self):
        rename_map={}
        actual_cols=self.df.columns.to_list()
        new_keys=[]
        for key in actual_cols: 
            for suffix, col_name in self.mapping.items():
                if f"_{suffix}" in key:
                    new_key= key.replace(f"_{suffix}", f"_{col_name}")
                    rename_map[key] = new_key
                    new_keys.append(new_key)
                    break
        return rename_map,new_keys
    





"""
    def __MTAD_GAT(self):
        results = []
        for index, row in self.df.iterrows():
            # Extracting values for A_Pred_Global and A_Score_Global from the current row
            is_anomaly = bool(row.get(mtad_gat_keys.MTAD_GAT_OUT_PREDICTION_GLOBAL))
            score = row.get(mtad_gat_keys.MTAD_GAT_OUT_SCORE_GLOBAL)
            threshold = row.get(mtad_gat_keys.MTAD_GAT_OUT_THRESHOLD_GLOBAL)
            # Constructing the value dictionary dynamically
            prediction_values = {column: row[column] for column in row.index} 
            updated_prediction_values = {}
            # Iterate through prediction_values to replace keys
            for key, value in prediction_values.items():
                for suffix, col_name in self.mapping.items():
                    if f"_{suffix}" in key:
                        new_key = key.replace(f"_{suffix}", f"_{col_name}")
                        updated_prediction_values[new_key] = value
                        break
                else:
                    # For keys that do not have a suffix, retain them as is
                    updated_prediction_values[key] = value

            
            timestamp = index.strftime(settings.DATE_TIME_FORMAT) # type: ignore
            result_entry = {
                    TIMESTAMP: timestamp,
                    IS_ANOMALY: is_anomaly,
                    SCORE: score,
                    THRESHOLD: threshold,
                    PREDICTION_VALUES: updated_prediction_values
                    } 
            results.append(result_entry)   
        return results

"""