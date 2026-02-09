import os
import sys

import numpy as np
import pandas as pd
import torch.nn as nn
import torch 
from torchinfo import summary
from adbox.commons import EscapeInfo
from adbox.mtad_gat_pytorch.utils import SlidingWindowDataset,create_data_loaders
from adbox.mtad_gat_pytorch.mtad_gat import MTAD_GAT
from adbox.mtad_gat_pytorch.training import Trainer
from adbox.mtad_gat_pytorch.utils import plot_losses
from adbox.mtad_gat_pytorch.prediction_alab import Predictor
from adbox.data_manager.data_storage_manager import DataStorageManager 
from adbox.data_manager.data_retrieval_manager import DataRetrievalManager
from adbox.config_manager.config_manager import TrainConfigManager
import adbox.mtad_gat_pytorch.mtad_gat_keys as keys  
import adbox.settings as settings
import logging
import os

logger = logging.getLogger(__name__)
logger.setLevel(settings.DEFAULT_LOGGING_LEVEL)





""" This module contains a function to train and test MTAD-GAT models.
This adapts and extends ML4ITS/mtad_gat_pytorch/train.py module.
"""

def train_MTAD_GAT(train_data:np.ndarray,
                   test_data:np.ndarray|None,
                   train_timestamps:pd.Index,
                   test_timestamps:pd.Index,
                   config_input:dict,
                   test_labels=None) -> tuple[dict[str, list[int]], pd.DataFrame, pd.DataFrame]:
    """
    Trains a MTAD-GAT model for anomaly detection.
    Args:
        train_data (np.ndarray): A 2D numpy array representing the training data, where rows correspond to 
                                 timestamp (assuming regular granularity) and columns to features.
        test_data (np.ndarray | None): A 2D numpy array representing the test data, similar to train data.If None, only training 
                                       will be performed without testing. 
        train_timestamps (pd.Index): A pandas Index object representing the timestamps associated with the 
                                     training data.
        test_timestamps (pd.Index): A pandas Index object representing the timestamps associated with the 
                                    test data. Only used if `test_data` is provided.
        config_input (dict): The dictionary containing configuration parameters inherited from the use-case (epochs and window_size).
        test_labels (Optional): Ground truth labels for the test data, used for evaluation (if available). 
                                Defaults to None.

    Returns:
        tuple[dict[str, list[int]], pd.DataFrame, pd.DataFrame]:
            - dict[str, list[int]]: Training statistics.
            - pd.DataFrame: The DataFrame containing the model's predictions for the training data.
            - pd.DataFrame: The DataFrame containing the model's predictions for the test data (if `test_data` is provided).


    """
    #Add checks on the input length
    ######
    ### preparation configuaration, data management, logs
    ######

    if train_data is None: raise(ValueError("Input train given is None"))

    # define logs directory
    log_dir = os.path.join(settings.LOGS_FOLDER,'train_logs')
 

    # create data managememt objects
    
    data_storage_manager = DataStorageManager() 
    data_retrival_manager = DataRetrievalManager()

    # complete and store training configuration

    conf_manager=TrainConfigManager()
    config=conf_manager.get_full_config(config_input)
    data_storage_manager.save_training_config(config)

    ## name variable from training configuration parameters    

    window_size = config.get(keys.MTAD_GAT_WINDOW_SIZE)
    spec_res = config.get(keys.MTAD_GAT_SPEC_RES)
    n_epochs :int = config.get(keys.MTAD_GAT_EPOCHS) # type: ignore
    batch_size = config.get(keys.MTAD_GAT_BS)
    init_lr = config.get(keys.MTAD_GAT_INIT_LR)
    val_split = config.get(keys.MTAD_GAT_VAL_SPLIT)
    shuffle_dataset = config.get(keys.MTAD_GAT_SHUFFLE_DATASET)
    use_cuda = config.get(keys.MTAD_GAT_USE_CUDA)
    print_every = config.get(keys.MTAD_GAT_PRINT_EVERY)
    log_tensorboard = config.get(keys.MTAD_GAT_LOG_TENSORBOARD)
    args_summary = str(config)

    threads_torch=min(torch.get_num_threads(),config.get(keys.MTAD_GAT_THREADS, sys.maxsize))
    torch.set_num_threads(threads_torch)

    #check if test data avaliable
    exist_test_data = test_data.shape[0]!=0 
    EscapeInfo(f"Test data avaliable during training: {exist_test_data}",log=logger)

    ######
    ### preparation data
    ######

    ##Convert train and test data to torch tensors
    x_train = torch.from_numpy(train_data).float()
    if exist_test_data: x_test = torch.from_numpy(test_data).float()
    else: x_test = None

    #get number of input features and lables for testing (if any)
    n_features = x_train.shape[1]
    y_test=test_labels

    #force number output feature equal to input
    out_dim = n_features
    target_dims = None # this line is inherited from ML4ITS/mtad_gat_pytorch and serves to call functions with desired parameter later
    #EscapeInfo(f"Will forecast and reconstruct all {n_features} input features")


    # Create dataset of sliding windows 
    train_dataset = SlidingWindowDataset(x_train, window_size, target_dims)
    if exist_test_data: test_dataset = SlidingWindowDataset(x_test, window_size, target_dims)
    else:  test_dataset = None

    #create data loader for training and testing the model 
    train_loader, val_loader, test_loader = create_data_loaders(
        train_dataset, batch_size, val_split, shuffle_dataset, test_dataset=test_dataset
    )

    ######
    ### preparation ML model
    ######

    #create MTAD_GAT object
    model = MTAD_GAT(
        n_features,
        window_size,
        out_dim,
        kernel_size=config.get(keys.MTAD_GAT_KERNEL_SIZE), # type: ignore
        use_gatv2=config.get(keys.MTAD_GAT_USE_GATV2), # type: ignore
        feat_gat_embed_dim=config.get(keys.MTAD_GAT_FEAT_GAT_EMBED_DIM),
        time_gat_embed_dim=config.get(keys.MTAD_GAT_TIME_GAT_EMBED_DIM),
        gru_n_layers=config.get(keys.MTAD_GAT_GRU_N_LAYERS), # type: ignore
        gru_hid_dim=config.get(keys.MTAD_GAT_GRU_HID_DIM), # type: ignore
        forecast_n_layers=config.get(keys.MTAD_GAT_FC_N_LAYERS), # type: ignore
        forecast_hid_dim=config.get(keys.MTAD_GAT_FC_HID_DIM), # type: ignore
        recon_n_layers=config.get(keys.MTAD_GAT_RECON_N_LAYERS), # type: ignore
        recon_hid_dim=config.get(keys.MTAD_GAT_RECON_HID_DIM), # type: ignore
        dropout=config.get(keys.MTAD_GAT_DROPOUT), # type: ignore
        alpha=config.get(keys.MTAD_GAT_ALPHA) # type: ignore
    )

    #select optimizer,  forecast criterion and recontructions criterion
    optimizer = torch.optim.Adam(model.parameters(), lr=init_lr) 
    forecast_criterion = nn.MSELoss()
    recon_criterion = nn.MSELoss()

    #create trainer object
    trainer = Trainer(
        model,
        optimizer,
        window_size,
        n_features,
        target_dims,
        n_epochs,
        batch_size,
        init_lr,
        forecast_criterion,
        recon_criterion,
        use_cuda,
        #save_path,
        log_dir,
        print_every,
        log_tensorboard,
        args_summary
    )
    
    #Log summary of the model
    #logger.info(summary(trainer.model, input_size=(batch_size, window_size, n_features)))

    ######
    ### Train
    ######

    # train model
    trainer.fit(train_loader, val_loader)


    #save losses
    data_storage_manager.save_losses(trainer.losses, plot=True)

    ######
    ### Test
    ######

    if exist_test_data:
        # Check test loss
        test_loss = trainer.evaluate(test_loader)
        print(f"Test forecast loss: {test_loss[0]:.5f}")
        print(f"Test reconstruction loss: {test_loss[1]:.5f}")
        print(f"Test total loss: {test_loss[2]:.5f}")


    reg_level = 0

    prediction_args = {keys.MTAD_GAT_TARGET_DIMS : target_dims, keys.MTAD_GAT_REG_LEVEL: reg_level}
    prediction_args.update({k:config.get(k) for k in keys.MTAD_GAT_PREDICTION_ARGUMENTS})



    predictor = Predictor(
        trainer.model,
        window_size,
        n_features,
        prediction_args,
    )


    label = y_test[window_size:] if y_test is not None else None
    train_pred_df, test_pred_df = predictor.predict_anomalies(x_train, x_test, label,train_timestamps[window_size:],test_timestamps[window_size:]) 
    # we denote every - window by its final timestamp
    
    # Save anomaly predictions made
    data_storage_manager.save_training_outputs(train_pred_df, test_pred_df)

    training_output = {
    keys.MTAD_GAT_OUT_EPOCHS_IDS: list(range(1, n_epochs + 1))
    } 
    
    training_output.update(trainer.losses)
 
    return training_output,train_pred_df, test_pred_df
