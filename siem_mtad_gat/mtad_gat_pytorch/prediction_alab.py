import json
from tqdm import tqdm
import pandas as pd
import torch
from siem_mtad_gat.mtad_gat_pytorch.eval_methods import *
from siem_mtad_gat.mtad_gat_pytorch.utils import SlidingWindowDataset
from siem_mtad_gat.data_manager.data_storage_manager import DataStorageManager
import siem_mtad_gat.settings as settings
import siem_mtad_gat.settings as settings
import logging
import os
os.makedirs(settings.OUTPUT_LOGS, exist_ok=True)
logging.basicConfig(filename=settings.LOGGING_FILE_NAME.format(name=__name__), format=settings.DEFAULT_LOGGING_FORMAT)
logger = logging.getLogger(__name__)
logger.setLevel(settings.DEFAULT_LOGGING_LEVEL)


""" This module contains the adapted and extended 
Prodictor class from ML4ITS/mtad_gat_pytorch/preprocess.py
to work within ADBox framework.
"""


class Predictor:
    """MTAD-GAT predictor class.

    :param model: MTAD-GAT model (pre-trained) used to forecast and reconstruct
    :param window_size: Length of the input sequence
    :param n_features: Number of input features
    :param pred_args: params for thresholding and predicting anomalies

    """

    def __init__(self, model, window_size, n_features, pred_args, batch_size : int = 256):
        self.model = model
        self.window_size = window_size
        self.n_features = n_features
        self.target_dims = pred_args.get("target_dims")
        self.scale_scores = pred_args.get("scale_scores")
        self.q = pred_args.get("q")
        self.level = pred_args.get("level")
        self.dynamic_pot = pred_args.get("dynamic_pot")
        self.use_mov_av = pred_args.get("use_mov_av")
        self.gamma = pred_args.get("gamma")
        self.reg_level = pred_args.get("reg_level")
        self.batch_size = batch_size
        self.use_cuda = True
        self.pred_args = pred_args

    def get_score(self, values):
        """Method that calculates anomaly score using given model and data
        :param values: 2D array of multivariate time series data, shape (N, k)
        :return np array of anomaly scores + dataframe with prediction for each channel and global anomalies
        """

        print("Predicting and calculating anomaly scores..")
        data = SlidingWindowDataset(values, self.window_size, self.target_dims)
        loader = torch.utils.data.DataLoader(data, batch_size=self.batch_size, shuffle=False)
        device = "cuda" if self.use_cuda and torch.cuda.is_available() else "cpu"

        self.model.eval()
        preds = []
        recons = []
        with torch.no_grad():
            for x, y in tqdm(loader):
                x = x.to(device)
                y = y.to(device)

                y_hat, _ = self.model(x)

                # Shifting input to include the observed value (y) when doing the reconstruction
                recon_x = torch.cat((x[:, 1:, :], y), dim=1)
                _, window_recon = self.model(recon_x)

                preds.append(y_hat.detach().cpu().numpy())
                # Extract last reconstruction only
                recons.append(window_recon[:, -1, :].detach().cpu().numpy())

        preds = np.concatenate(preds, axis=0)
        recons = np.concatenate(recons, axis=0)
        actual = values.detach().cpu().numpy()[self.window_size:]

        if self.target_dims is not None:
            actual = actual[:, self.target_dims]

        anomaly_scores = np.zeros_like(actual)
        df_dict = {}
        for i in range(preds.shape[1]):
            df_dict[f"Forecast_{i}"] = preds[:, i]
            df_dict[f"Recon_{i}"] = recons[:, i]
            df_dict[f"True_{i}"] = actual[:, i]
            a_score = np.sqrt((preds[:, i] - actual[:, i]) ** 2) + self.gamma * np.sqrt(
                (recons[:, i] - actual[:, i]) ** 2)

            if self.scale_scores:
                q75, q25 = np.percentile(a_score, [75, 25])
                iqr = q75 - q25
                median = np.median(a_score)
                a_score = (a_score - median) / (1+iqr)

            anomaly_scores[:, i] = a_score
            df_dict[f"A_Score_{i}"] = a_score

        df = pd.DataFrame(df_dict)
        anomaly_scores = np.mean(anomaly_scores, 1)
        df['A_Score_Global'] = anomaly_scores

        return df

    def predict_anomalies(self, 
                          train:torch.Tensor, 
                          test, 
                          true_anomalies=None, 
                          train_timestamps:pd.Index=[], 
                          test_timestamps:pd.Index=[], 
                          load_scores : bool = False, 
                          save_output : bool = True,
                          scale_scores:bool=False,
                          only_predict:bool=False,
                          method:str="pot")-> tuple[pd.DataFrame,pd.DataFrame]:
  
        """Predicts anomalies in multivariate time series data.
        If called for prediction only:
         - set only_predict=True
         - input all point as first argument (train) 
         - test is expected to be None

        Args:
            train (torch.Tensor): 2D array of train multivariate time series data.
            test : 2D array of test multivariate time series data.
            true_anomalies (torch.Tensor): True anomalies of the test set, or None if not available.
            train_timestamps (pd.Index): Timestamps corresponding to the train data.
            test_timestamps (pd.Index): Timestamps corresponding to the test data.
            load_scores (bool, optional): Whether to load anomaly scores instead of calculating them. Defaults to False.
            save_output (bool, optional): Whether to save the output dataframe. Defaults to True.
            scale_scores (bool, optional): Whether to feature-wise scale anomaly scores. Defaults to False.
            only_predict (bool, optional): True if called from predict function. Defaults to False.
            method (str, optional): Method used for threshold computation. Defaults to "pot". Alternative "epsilon".

        Returns:
            pd.DataFrame: prediction for train set
            pd.DataFrame: prediction for test set
        """

        if load_scores:
            raise NotImplementedError(f"Loading features's score for prediction not implemented")
        else:
            train_pred_df = self.get_score(train) 
            test_pred_df = self.get_score(test) if test!=None else None
            

            train_anomaly_scores = train_pred_df.get('A_Score_Global').values
            test_anomaly_scores = test_pred_df.get('A_Score_Global').values if test!=None else None

            #train_anomaly_scores = adjust_anomaly_scores(train_anomaly_scores, self.dataset, True, self.window_size)
            #test_anomaly_scores = adjust_anomaly_scores(test_anomaly_scores, self.dataset, False, self.window_size)

            # Update df
            train_pred_df['A_Score_Global'] = train_anomaly_scores
            if test!=None: test_pred_df['A_Score_Global'] = test_anomaly_scores 
            
           

        if self.use_mov_av:
            smoothing_window = int(self.batch_size * self.window_size * 0.05)
            train_anomaly_scores = pd.DataFrame(train_anomaly_scores).ewm(span=smoothing_window).mean().values.flatten()
            test_anomaly_scores = pd.DataFrame(test_anomaly_scores).ewm(span=smoothing_window).mean().values.flatten() if test != None else  None

        # Find threshold and predict anomalies at feature-level (for plotting and diagnosis purposes)
        out_dim = self.n_features if self.target_dims is None else len(self.target_dims)
        #all_preds = np.zeros((len(test_pred_df), out_dim)) if test != None else  None # necessity of all_preds (?)

        for i in range(out_dim):
            train_feature_anom_scores = train_pred_df.get(f"A_Score_{i}").values
            test_feature_anom_scores = test_pred_df.get(f"A_Score_{i}").values if test != None else  None

            if method=="pot":
                th_pot,index_anom,init_th = pot_eval(train_feature_anom_scores, test_feature_anom_scores, true_anomalies,only_predict,
                          q=self.q, level=self.level, dynamic=self.dynamic_pot,feature=i)
                # if in prediction only mode, the train set is the input set, in that case anomaly indices are the train set once ####SEEEE if shift needed
                # while in train it is used to compute the init_th
                # in such a case, we consider train set's peaks as anomalies
                train_feature_anom_preds =  (train_feature_anom_scores >= th_pot).astype(int)  if only_predict else (train_feature_anom_scores >= init_th).astype(int) 
                test_feature_anom_preds =  (test_feature_anom_scores >= th_pot).astype(int)  if test != None else  None 
    
                train_pred_df[f"Thresh_{i}"] = th_pot if only_predict else init_th
                if test != None : test_pred_df[f"Thresh_{i}"] = th_pot

            elif method=="epsilon":     
                epsilon = find_epsilon(train_feature_anom_scores, reg_level=2)
                train_feature_anom_preds = (train_feature_anom_scores >= epsilon).astype(int)
                test_feature_anom_preds = (test_feature_anom_scores >= epsilon).astype(int) if test != None else  None
                train_pred_df[f"Thresh_{i}"] = epsilon
                if test != None : test_pred_df[f"Thresh_{i}"] = epsilon 
            else:
                logger.error(f"Invalid prediction method. method is {method}.")

            train_pred_df[f"A_Pred_{i}"] = train_feature_anom_preds
            if test != None : test_pred_df[f"A_Pred_{i}"] = test_feature_anom_preds 

            #if test != None: all_preds[:, i] = test_feature_anom_preds

        # Global anomalies (entity-level) are predicted using aggregation of anomaly scores across all features
        # These predictions are used to evaluate performance, as true anomalies are labeled at entity-level
        # Evaluate using different threshold methods: brute-force, epsilon and peaks-over-treshold
        """
        e_eval = epsilon_eval(train_anomaly_scores, test_anomaly_scores, true_anomalies, reg_level=self.reg_level)
        th_pot,index_anom,init_th = pot_eval(train_anomaly_scores, test_anomaly_scores, true_anomalies,only_predict,
                          q=self.q, level=self.level, dynamic=self.dynamic_pot)
        if true_anomalies is not None:
            bf_eval = bf_search(test_anomaly_scores, true_anomalies, start=0.01, end=2, step_num=100, verbose=False)
        else:
            bf_eval = {}

        logger.info(f"Results using epsilon method:\n {e_eval}")
        logger.info(f"Results using peak-over-threshold method:\n { init_th }")
        logger.info(f"Results using best f1 score search:\n {bf_eval}")


        for k, v in e_eval.items():
            if not type(e_eval[k]) == list:
                e_eval[k] = float(v)
        #for k, v in p_eval.items():
        #    if not type(p_eval[k]) == list:
        #        p_eval[k] = float(v)
        for k, v in bf_eval.items():
            bf_eval[k] = float(v)
        """
        # Save
        #summary = {"epsilon_result": e_eval, "pot_result": p_eval, "bf_result": bf_eval}
        #if save_output:
            #data_storage_manager = DataStorageManager() 
            #data_storage_manager.save_summary(summary)

        if method=="pot":
            # if in prediction only mode, the train set is the input set, in that case we use dynamic threshold
            # while in train it is used to compute the init_th
            # in such a case, we consider train set's peaks as anomalies
            th_pot,index_anom,init_th = pot_eval(train_anomaly_scores, test_anomaly_scores, true_anomalies,only_predict,
                          q=self.q, level=self.level, dynamic=self.dynamic_pot)
            train_anom_preds = (train_anomaly_scores >= th_pot).astype(int)  if only_predict else (train_anomaly_scores >= init_th).astype(int) 
            test_anom_preds =   (test_anomaly_scores >= th_pot).astype(int)  if test != None else  None 

            if test != None: test_pred_df["A_True_Global"] = true_anomalies

            train_pred_df["Thresh_Global"] = th_pot if only_predict else init_th
            if test != None:  test_pred_df["Thresh_Global"] = init_th
            train_pred_df[f"A_Pred_Global"] =train_anom_preds
            if test != None: test_pred_df[f"A_Pred_Global"] = test_anom_preds
            print()
        else:
            e_eval = epsilon_eval(train_anomaly_scores, test_anomaly_scores, true_anomalies, reg_level=self.reg_level)
            global_epsilon = e_eval["threshold"]
            if test != None: test_pred_df["A_True_Global"] = true_anomalies
            train_pred_df["Thresh_Global"] = global_epsilon
            if test != None:  test_pred_df["Thresh_Global"] = global_epsilon
            train_pred_df[f"A_Pred_Global"] = (train_anomaly_scores >= global_epsilon).astype(int)
            if test != None: test_preds_global = (test_anomaly_scores >= global_epsilon).astype(int)
            # Adjust predictions according to evaluation strategy
            if true_anomalies is not None:
                    test_preds_global = adjust_predicts(None, true_anomalies, global_epsilon, pred=test_preds_global)
            if test != None: test_pred_df[f"A_Pred_Global"] = test_preds_global

        #Add timestamps as index

        train_pred_df["window_start"]=train_timestamps
        train_pred_df.set_index("window_start", inplace=True)
        if test != None: 
            test_pred_df["window_start"]=test_timestamps
            test_pred_df.set_index("window_start", inplace=True)
        print("-- Done.")

        return train_pred_df,test_pred_df
