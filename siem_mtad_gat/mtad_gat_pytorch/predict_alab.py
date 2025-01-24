import torch 
import pandas as pd
import numpy as np
import siem_mtad_gat.mtad_gat_pytorch.mtad_gat_keys as keys

from siem_mtad_gat.commons import EscapeError, EscapeInfo
from siem_mtad_gat.mtad_gat_pytorch.mtad_gat import MTAD_GAT
from siem_mtad_gat.mtad_gat_pytorch.prediction_alab import Predictor
from siem_mtad_gat.data_manager.data_retrieval_manager import DataRetrievalManager
from siem_mtad_gat.mtad_gat_pytorch import *

logger = logging.getLogger(__name__)
logger.setLevel(settings.DEFAULT_LOGGING_LEVEL)





""" This module contains a function to train and test MTAD-GAT models.
This adapts and extends ML4ITS/mtad_gat_pytorch/train.py module.
"""

def predict_MTAD_GAT(
        data: np.ndarray, 
        timestamps: pd.Index, 
        save_output: bool = False
        )  -> None | tuple[pd.DataFrame, pd.DataFrame]: 
    """Runs a pretrained MTAD-GAT model to generate anomaly predictions

    Args:
        data (pd.DataFrame): preprocees data-frame 
        timestamps (pd.Index): timestamps of the points in the data-frame (used for mapping output to orginal input)
        save_output (bool, optional): If True, dumps the summary of predictions and the output-frame in dedicated files. Defaults to False.

    Returns:
        tuple[pd.DataFrame,pd.DateFrame]:
         - dataframe containing for each window, both feature-wise and global anomaly scores.
         - sub dataframe containing only the entries marked as anomalies
    """
    ######
    ### preparation configuaration, data management, logs
    ######


    # create data managememt objects
    data_retrival_manager = DataRetrievalManager()
    # retrieve training configuration
    config : dict = data_retrival_manager.retrieve_training_config()

    ## name variable from prediction configuration parameters    
    
    # Check if config is empty # The pipeline should fail before arriving here
    if config is {}:
        raise EscapeError("Retrieve training configuration is empry",logger)

 
    window_size = config.get(keys.MTAD_GAT_WINDOW_SIZE)

    ######
    ### preparation data
    ######

    ##Convert train and test data to torch tensors
    x_train = torch.from_numpy(data).float()
    x_test = None

    #get number of input features and lables for testing (if any)
    n_features = x_train.shape[1]

    #force number output feature equal to input
    out_dim = n_features
    target_dims = None # this line is inherited from ML4ITS/mtad_gat_pytorch and serves to call functions with desired parameter later
    EscapeInfo(f"Will forecast and reconstruct all {n_features} input features",logger)

    ######
    ### preparation ML model
    ######

    #create MTAD_GAT object
    model = MTAD_GAT(
        n_features,
        window_size,
        out_dim,
        kernel_size=config.get(keys.MTAD_GAT_KERNEL_SIZE), # type: ignore
        use_gatv2=config.get(keys.MTAD_GAT_USE_GATV2),# type: ignore
        feat_gat_embed_dim=config.get(keys.MTAD_GAT_FEAT_GAT_EMBED_DIM),# type: ignore
        time_gat_embed_dim=config.get(keys.MTAD_GAT_TIME_GAT_EMBED_DIM),# type: ignore
        gru_n_layers=config.get(keys.MTAD_GAT_GRU_N_LAYERS),# type: ignore
        gru_hid_dim=config.get(keys.MTAD_GAT_GRU_HID_DIM),# type: ignore
        forecast_n_layers=config.get(keys.MTAD_GAT_FC_N_LAYERS),# type: ignore
        forecast_hid_dim=config.get(keys.MTAD_GAT_FC_HID_DIM),# type: ignore
        recon_n_layers=config.get(keys.MTAD_GAT_RECON_N_LAYERS),# type: ignore
        recon_hid_dim=config.get(keys.MTAD_GAT_RECON_HID_DIM),# type: ignore
        dropout=config.get(keys.MTAD_GAT_DROPOUT),# type: ignore
        alpha=config.get(keys.MTAD_GAT_ALPHA)# type: ignore
    )

    # Retrive model
    device = "cuda" if config.get(keys.MTAD_GAT_USE_CUDA) and torch.cuda.is_available() else "cpu"
    data_retrival_manager.load_model(model, device=device)
 
    ######
    ### Predict
    ######

    reg_level = 0

    prediction_args = {keys.MTAD_GAT_TARGET_DIMS : target_dims, keys.MTAD_GAT_REG_LEVEL: reg_level}
    prediction_args.update({k:config.get(k) for k in keys.MTAD_GAT_PREDICTION_ARGUMENTS})

    predictor = Predictor(
        model,
        window_size,
        n_features,
        prediction_args,
    )

    pred_df,_ = predictor.predict_anomalies(x_train, x_test, None,timestamps[window_size:],pd.Index([]),only_predict=True) # we denote every - window by its final timestamp 
    
    anomalies = pred_df[pred_df[keys.MTAD_GAT_OUT_PREDICTION_GLOBAL] !=0]

    if save_output:
        raise NotImplementedError(f"Save output prediction not implemented")

    return pred_df, anomalies

