import os
import torch.nn as nn
import torch 
import pandas as pd
from torchinfo import summary
import numpy as np
from siem_mtad_gat.mtad_gat_pytorch.utils import SlidingWindowDataset,create_data_loaders
from siem_mtad_gat.mtad_gat_pytorch.mtad_gat import MTAD_GAT
from siem_mtad_gat.mtad_gat_pytorch.training import Trainer
from siem_mtad_gat.mtad_gat_pytorch.utils import plot_losses
from siem_mtad_gat.mtad_gat_pytorch.prediction_alab import Predictor
from siem_mtad_gat.data_manager.data_storage_manager import DataStorageManager 
from siem_mtad_gat.data_manager.data_retrieval_manager import DataRetrievalManager
from siem_mtad_gat.config_manager.config_manager import TrainConfigManager  
import siem_mtad_gat.settings as settings
import logging
import os
os.makedirs(settings.OUTPUT_LOGS, exist_ok=True)
logging.basicConfig(filename=settings.LOGGING_FILE_NAME.format(name=__name__), format=settings.DEFAULT_LOGGING_FORMAT)
logger = logging.getLogger(__name__)
logger.setLevel(settings.DEFAULT_LOGGING_LEVEL)



""" This module contains a function to train and test MTAD-GAT models.
This adapts and extends ML4ITS/mtad_gat_pytorch/train.py module.
"""

def predict_MTAD_GAT(
        data: np.array, 
        timestamps: pd.Index, 
        save_output: bool = False
        ) -> pd.DataFrame: 
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
    config = data_retrival_manager.retrieve_training_config()

    ## name variable from prediction configuration parameters    
    
    # Check if config is None 
    if config is None:
        logging.error("Config object is None")
        return 

 
 
    window_size = config.get("window_size")

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
    logger.info(f"Will forecast and reconstruct all {n_features} input features")

    ######
    ### preparation ML model
    ######

    #create MTAD_GAT object
    model = MTAD_GAT(
        n_features,
        window_size,
        out_dim,
        kernel_size=config.get("kernel_size"),
        use_gatv2=config.get("use_gatv2"),
        feat_gat_embed_dim=config.get("feat_gat_embed_dim"),
        time_gat_embed_dim=config.get("time_gat_embed_dim"),
        gru_n_layers=config.get("gru_n_layers"),
        gru_hid_dim=config.get("gru_hid_dim"),
        forecast_n_layers=config.get("fc_n_layers"),
        forecast_hid_dim=config.get("fc_hid_dim"),
        recon_n_layers=config.get("recon_n_layers"),
        recon_hid_dim=config.get("recon_hid_dim"),
        dropout=config.get("dropout"),
        alpha=config.get("alpha")
    )

    # Retrive model
    device = "cuda" if config.get("use_cuda") and torch.cuda.is_available() else "cpu"
    data_retrival_manager.load_model(model, device=device)
 
    ######
    ### Predict
    ######

    reg_level = 0

    prediction_args = {
        "target_dims": target_dims,
        'scale_scores': config.get("scale_scores"),
        "level": config.get("level"),
        "q": config.get("q"),
        'dynamic_pot': config.get("dynamic_pot"),
        "use_mov_av": config.get("use_mov_av"),
        "gamma": config.get("gamma"),
        "reg_level": reg_level,
    }

    predictor = Predictor(
        model,
        window_size,
        n_features,
        prediction_args,
    )

    pred_df,_ = predictor.predict_anomalies(x_train, x_test, None,timestamps[:-window_size],[],only_predict=True) # we denote every - window by its initial timestamp 
    
    anomalies = pred_df[pred_df['A_Pred_Global'] !=0]

    if save_output:
        raise NotImplementedError(f"Save output prediction not implemented")

    return pred_df, anomalies

