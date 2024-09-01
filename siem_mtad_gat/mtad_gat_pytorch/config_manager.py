import json
import siem_mtad_gat.settings as settings

""" The config manager include the implementation of all the
classes use to manage the configuration of machine learning operation
such as preprocessing, training and predicting."""



class PreprocessConfigManager:
    """Preprocessing configuration manager
    
    Attributes:
        config_path : (str, optional)
            The path to the configuration file. If not provided, defaults to None.
        default_config_path : str
            The default path to the configuration file.
        config : dict or None
            The preprocessing configuration dictionary. Initialized as None.

    Methods: 
         load_config
         save config_file

    """


    def __init__(self,  config_path=None): #option 2 config path -> config dictionary
        """Constructor

        Args:
            config_path (str, optional): the path to the custume config file. Defaults to None.
        """
        self.config_path = config_path
        self.default_config_path = settings.MTAD_GAT_CONFIG_PREPROCESSING_DEFAULT 

    def load_config(self,verbose=False) -> dict :
        """load configuration dictionary and complete missing values with default configuration.

        Args:
            verbose (bool, optional): Defaults to False.

        Raises:
            Exception: custom config file does not exists

        Returns:
            dict: the configuration args for the preprocessing.
        """
        if  self.config_path == None : 
            self.config_path = self.default_config_path
            
        try: 
           with open(self.config_path, "r") as file:
                self.config = json.load(file)  
        except:
            raise Exception(f"<{self.config_path}> does not exist.")
        
        # add here more check for format input config?
        assert ('columns' in self.config.keys())
        assert ('granularity' in self.config.keys())

        if verbose: print(self.config)

        return self.config 

    def save_config_file(self, out_path : str):
        """Saves the current training configuration to the specified output file path.

        Args:
            out_path (str): The path to file where saving self.config dictionary

        Raises:
            Exception: Output config does not exist.
        """
        if self.config != None :
            with open(out_path, "w") as out_file:
                json.dump(self.config, out_file,indent=2)
        else:
            raise Exception("Config does not exist.")   


class TrainConfigManager:
    """Training configuration manager

    Attributes:
        config_path (str): 
            The file path to the custom configuration file.
        train_config (dict or None): 
            The training configuration dictionary. Defaults to None.
        default_config_path (str): 
            The path for the file containing the default configuration arguments and types.

    Methods: 
        load_config
        save config_file        
    """
    def __init__(self, config_path : str): 
        self.config_path = config_path
        self.train_config = None 
        self.default_config_path=settings.MTAD_GAT_CONFIG_TRAINING_DEFAULT 

    def load_config(self,verbose=False) -> dict: ## this can be made statless
        """oad configuration dictionary and complete missing values with default configuration.

        Args:
            verbose (bool, optional): Defaults to False.

        Raises:
            Exception: missing input config file
            Exception: missing default config file
            Exception: Type error in input configuration.

        Returns:
            dict: the configuration args for the training
        """
        try: 
           with open(self.config_path, "r") as file:
               input_config=json.load(file)  
        except:
            raise Exception(f"<{self.config_path}> does not exist.")

        try: 
           with open(self.default_config_path, "r") as file:
               default_config=json.load(file)  
        except:       
            raise Exception("train_config_default_args.json does not exist.")
        
        self.train_config={}
        for key in default_config.keys():
                    try:
                        key_val = input_config[key]
                        if key_val == None or (type(key_val) is eval(default_config[key]['type'])):
                            self.train_config[key] = key_val
                        else: 
                            try:
                                self.train_config[key] = eval(input_config[key]['type'])(key_val)
                            except TypeError:
                                raise Exception(f"TypeError: {key} expected type is {default_config[key]['type']}!") # for floats ex. use 3.0 not 3
                    except KeyError:
                        self.train_config[key] = default_config[key]['default']
        if verbose: print(self.train_config)
        return self.train_config

    def save_config_file(self, out_path):
        """Saves the current training configuration to the specified output file path.

        Args:
            out_path (str): The path to file where saving self.config dictionary

        Raises:
            Exception: Output config does not exist.
        """
        if self.train_config != None :
            with open(out_path, "w") as out_file:
                json.dump(self.train_config, out_file,indent=2)
        else:
            raise Exception("Config does not exist.")

if __name__ == "__main__":
    conf_manager=TrainConfigManager('/home/alab/siem-mtad-gat/siem_mtad_gat/mtad_gat_pytorch/train_config_example_input.json')
    my_config=conf_manager.load_config()
    conf_manager.save_config_file("/home/alab/siem-mtad-gat/siem_mtad_gat/mtad_gat_pytorch/train_config.json")
    #conf_manager.save_config_file("try_save_config.json")

"""
Example of default training config file
train_config = {
  "window_size" :  { "type" : "int" , "default" : 100  },
  "spec_res" :  { "type" : "bool", "default" : False },
    # -- Model params ---
    # 1D conv layer
   "kernel_size" :  { "type" : "int", "default" :7 },
   "use_gatv2" :  {"type" : "bool", "default" :True },
   "feat_gat_embed_dim" :  { "type" : "int", "default" :None },
   "time_gat_embed_dim" :  { "type" : "int", "default" :None },
    # GRU layer
   "gru_n_layers" :  {  "type" : "int", "default" :1 },
   "gru_hid_dim" :  {  "type" : "int", "default" :150 },
    # Forecasting Model
   "fc_n_layers" :  {  "type" : "int", "default" :3 },
   "fc_hid_dim" :  { "type" : "int", "default" :150 },
    # Reconstruction Model
   "recon_n_layers" :  { "type" : "int", "default" :1 },
   "recon_hid_dim" :  { "type" : "int", "default" :150 },
    # Other
   "alpha" :  { "type" : "float", "default" :0.2 },
    # --- Train params ---
   "epochs" :  { "type" : "int", "default" :30 },
   "val_split" :  { "type" : "float", "default" :0.1 },
   "bs" :  { "type" : "int", "default" :256 },
   "init_lr" :  { "type" : "float", "default" :1e-3 },
   "shuffle_dataset" :  { "type" : "bool", "default" :True },
   "dropout" :  { "type" : "float", "default" :0.3 },
   "use_cuda" :  { "type" :"bool", "default" :True },
   "print_every" :  { "type" : "int", "default" :1 },
   "log_tensorboard" :  { "type" :"bool", "default" :True },

    # --- Predictor params ---
   "scale_scores" :  { "type" :"bool", "default" :False },
   "use_mov_av" :  { "type" :"bool", "default" :False },
   "gamma" :  { "type" : "float", "default" :1 },
   "level" :  { "type" : "float", "default" : None },
   "q" :  { "type" : "float", "default" : None },
   "dynamic_pot" :  { "type" :"bool", "default" :False },
 }   """