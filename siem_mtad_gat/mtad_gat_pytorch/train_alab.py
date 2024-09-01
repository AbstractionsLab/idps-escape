import os
import torch.nn as nn
import torch 
from torchinfo import summary
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

def train_MTAD_GAT(train_data, test_data, train_timestamps, test_timestamps,config_input, test_labels=None): 
    
    ######
    ### preparation configuaration, data management, logs
    ######

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

    window_size = config.get("window_size")
    spec_res = config.get("spec_res")
    n_epochs = config.get("epochs")
    batch_size = config.get("bs")
    init_lr = config.get("init_lr")
    val_split = config.get("val_split")
    shuffle_dataset = config.get("shuffle_dataset")
    use_cuda = config.get("use_cuda")
    print_every = config.get("print_every")
    log_tensorboard = config.get("log_tensorboard")
    args_summary = str(config)

    #check if test data avaliable
    exist_test_data = test_data.shape[0]!=0 
    logger.info(f"Test data avaliable during training: {exist_test_data}")

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
    logger.info(f"Will forecast and reconstruct all {n_features} input features")


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

    #select optimizer,  forecast criterion and recontructions criterion
    optimizer = torch.optim.Adam(model.parameters(), lr=config.get("init_lr"))
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

    #save model
    #TBD

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

    level = config.get("level")
    q = config.get("q")
    reg_level = 0

    #trainer.load(data_retrival_manager.model_path()) # why we need to load?

    prediction_args = {
        "target_dims": target_dims,
        'scale_scores': config.get("scale_scores"),
        "level": level,
        "q": q,
        'dynamic_pot': config.get("dynamic_pot"),
        "use_mov_av": config.get("use_mov_av"),
        "gamma": config.get("gamma"),
        "reg_level": reg_level,
        #"save_path": save_path,
    }
    best_model = trainer.model


    predictor = Predictor(
        best_model,
        window_size,
        n_features,
        prediction_args,
    )


    label = y_test[window_size:] if y_test is not None else None
    train_pred_df, test_pred_df = predictor.predict_anomalies(x_train, x_test, label,train_timestamps[:-window_size],test_timestamps[:-window_size]) # we denote every - window by its initial timestamp 
    
    # Save anomaly predictions made using epsilon method (could be changed to pot or bf-method)
    data_storage_manager.save_training_outputs(train_pred_df, test_pred_df)

    training_output = {
    "epochIds": list(range(1, n_epochs + 1))
    } 
    
    training_output.update(trainer.losses)
 
    return training_output
