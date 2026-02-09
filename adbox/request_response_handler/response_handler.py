from adbox.commons import EscapeError
from adbox.request_response_handler.blocks import BlockPrediction
from adbox.request_response_handler.keys import *
from adbox.request_response_handler import *
from adbox.time_manager import TimeManager




#Training

# errors
ERROR_ALGORITHM="Response method not implement for {alg}"
    

def prediction_pipeline_response(prediction_request, dataframe, column_names,out_interval_extrema,algorithm:str): 
    runmode=prediction_request.get(confkeys.UC_RUN_MODE).name
    # Building base the JSON object
    response: dict = {
            RESP_RUN_MODE: runmode,
            RESP_DETECTOR_ID: prediction_request.get(confkeys.UC_DETECTOR_ID),
            RESP_START_TIME: out_interval_extrema[0],
            RESP_END_TIME: out_interval_extrema[1],
            #RESP_RESULTS: []
    } 
    if runmode == settings.RUN_MODE.BATCH.name: response[confkeys.UC_BATCH_SIZE]=str(prediction_request.get(confkeys.UC_BATCH_SIZE))
    # Create a mapping from numeric suffix to column names
    mapping = {str(i): name for i, name in enumerate(column_names)}
    block=BlockPrediction(dataframe=dataframe,mapping=mapping).get_prediction_block(alg=algorithm)

    if block is None:  raise EscapeError(ERROR_ALGORITHM.format(alg=algorithm),logger)

    response[RESP_RESULTS] = block()
    
            
    return response

def training_pipeline_response(training_request:dict,train_response:dict,training_params:dict) -> dict:
    response : dict = {
        DETECTOR_ID: training_params.get(DETECTOR_ID),
        CREATION_TIME: training_params.get(CREATION_TIME),
        LAST_UPDATE_TIME: training_params.get(LAST_UPDATE_TIME),
        TRAIN_CONFIG: training_request.get(confkeys.UC_TRAIN_CONFIG, {}),
        MODEL_INFO: training_params.get(MODEL_INFO),
        DIAGNOSTIC_INFO: train_response
        }
    return response
       
        

def training_params(uuid,datasource_name): 
    params= {
        DETECTOR_ID : uuid, 
        CREATION_TIME:  TimeManager.now_str(),
        LAST_UPDATE_TIME: TimeManager.now_str(),
        MODEL_INFO: { 
            DATASOURCE_TRAIN: datasource_name, 
            STATUS: CREATED, 
            ERRORS: []
    }}
    return params

