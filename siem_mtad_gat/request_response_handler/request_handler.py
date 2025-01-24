from siem_mtad_gat.commons import EscapeError
from siem_mtad_gat.request_response_handler.blocks import BlockPrediction
from siem_mtad_gat.request_response_handler.response_handler import ERROR_ALGORITHM
from siem_mtad_gat.request_response_handler import *

def shipping_train_data_request(dataframe,column_names,algorithm):
    # Building base the JSON object
    # Create a mapping from numeric suffix to column names
    mapping = {str(i): name for i, name in enumerate(column_names)}
    blp=BlockPrediction(dataframe=dataframe,mapping=mapping)
    block=blp.get_prediction_block(alg=algorithm)
    if block is None:  raise EscapeError(ERROR_ALGORITHM.format(alg=algorithm),logger)
    request = block()

    return request,blp.feat_keys