import json
import os
import yaml
from adbox import settings
from adbox.ad_engine.mtad_gat.ad_engine import ADEngine
import re
from tabulate import tabulate

from adbox.config_manager.config_keys import *

# TO-REDESIGN (redesign and implement as robust use-case scenario creation/modification tool and adbox inspector with input validation)



class Console:
    def __init__(self,shipping:bool=False):
        self.engine=ADEngine(ship_to_indexer=shipping)


    def main(self):
        """
        Runs an interactive loop allowing the user to invoke methods from the AD engine to ingest data, train detectors and run predictions.
        """
        
        while True: 
            print("\nEnter a number and press enter to select an ADBox action to perform:")
            print("1. Train an anomaly detector")
            print("2. Predict anomalies using one of the available detectors")
            print("3. Select an existing anomaly detector for prediction")
            print("4. Exit")
            
            action = input("Enter a number (1-4): ").strip()
            
            if action == '1': 
                uc_n = self.select_input_training()
                train_request=self.engine.get_training_requests_from_uc(uc_number=uc_n)
                train_response = self.engine.training_pipeline(training_request=train_request)
                print("Training response: ", train_response)
            elif action == '2': 
                uc_n = self.select_input_prediction()
                pred_request=self.engine.get_prediction_requests_from_uc(uc_number=uc_n)
                self.engine.run_prediction_pipeline(prediction_request=pred_request,uc_number=uc_n)
            elif action == '3': 
                self.select_detector()            
            elif action == '4':
                print("Exiting the program...")
                break
            else:
                print("Invalid choice! Please try again.")

        
    def select_detector(self):
        """
        Prompts the user to select a detector ID from the list of available detectors.
        
        Returns:
            str: Selected detector ID.
        """ 
        if self.engine.current_detector_id is None:
            print("No trained detectors found! train a detector before prediction or selection. ") 
            return 
        else:
            print(f"\nThe current detector ID is: {self.engine.current_detector_id}") 
            print("\nBy default, all predictions will be done using this detector.") 
            change_detector = input("Do you wish to change the detector used for prediction? (y/n): ").strip().lower()
        
            if change_detector == 'y':
                print("\nSelect a detector among the following list of available detectors:") 
                detectors = self.engine.get_detectors()
                # Prepare the data for tabulate
                table_data = [] 
                for index, detector_info in enumerate(detectors, start=1): 
                    table_data.append([
                            index,
                            detector_info['detector_id'],
                            detector_info['display_name'],
                            detector_info['description']
                        ])

                headers = ["Index", "Detector ID", "Display Name", "Description"]

                print(tabulate(table_data, headers=headers, tablefmt="pretty"))


                while True:
                    try:
                        detector_selection = int(input("\nEnter the number corresponding to the detector ID and name you wish to select: "))
                        if 1 <= detector_selection <= len(detectors):
                            selected_id = detectors[detector_selection - 1]['detector_id'] 
                            self.engine.select(selected_id) 
                            print(f"\nThe current detector ID is: {self.engine.current_detector_id}")  
                            return selected_id
                        else:
                            print("Invalid selection! The default detector will be used.") 
                            return UC_DEFAULT 
                    except ValueError:
                        print("Invalid input! Please enter a number.") 

            elif change_detector == 'n':
                return UC_DEFAULT 
            else:
                print(f"Invalid input! The default detector will be used. ")
                return UC_DEFAULT 

    def compile_uc_training(self):
            uc_dict = dict()

            print(f"--- Key: {UC_INDEX_DATE}:" )
            if not use_default(): uc_dict[UC_INDEX_DATE]= select_date()

            print(f"--- Key: {UC_COLUMNS}:" )
            default_cols=use_default()
            if not default_cols: 
                uc_dict[UC_COLUMNS]=select_features()
                
            
            uc_dict[UC_AGGREGATION]=True
            print(f"--- Key: {UC_AGGREGATION_CONFIG}:" )
            agg_dict={}
            if not default_cols:  
                agg_dict[UC_FEATURES]={}
                for f in uc_dict.get(UC_COLUMNS,[]):
                    print(f"------ Feature: {f}:" )
                    agg_dict[UC_FEATURES][f]=set_aggr()

            print(f"--- Key: {UC_GRANULARITY}:" )
            if not use_default():
                agg_dict[UC_GRANULARITY]=select_granularity()

                uc_dict[UC_AGGREGATION_CONFIG]= agg_dict

            print(f"---Key: {UC_TRAIN_CONFIG}:" )
            if not use_default(): 
                uc_dict[UC_TRAIN_CONFIG]=select_train_config()
    
            print(f"--- Key: {UC_DISPLAY_NAME}:" )
            uc_dict[UC_DISPLAY_NAME]=select_name()  
            
            full_uc=dict()
            full_uc[UC_TRAINING]=uc_dict
            print(full_uc)   
            
            return full_uc


    def compile_uc_prediction(self):
            
            print(f"--- Key: {UC_RUN_MODE}:" )
            rm=select_run_mode()
            runmode=settings.RUN_MODE(rm)
            full_uc=dict()
            uc_dict=dict()
            uc_dict[UC_RUN_MODE]=settings.RUNMODE_LIST[rm-1]
            print(f"--- Key: {UC_DETECTOR_ID}:" )
            uc_dict[UC_DETECTOR_ID]=self.select_detector()
            full_uc[UC_PREDICTION]=uc_dict
            match runmode:
                case settings.RUN_MODE.HISTORICAL:
                    print(f"--- Key: {UC_START_TIME}:" )
                    if not use_default():uc_dict[UC_START_TIME]=select_time(UC_START_TIME)
                    print(f"--- Key: {UC_END_TIME}:" )
                    if not use_default():uc_dict[UC_END_TIME]=select_time(UC_END_TIME)
                    return full_uc
                case settings.RUN_MODE.BATCH:
                    print(f"--- Key: {UC_BATCH_SIZE}:" )
                    if not use_default(): uc_dict[UC_BATCH_SIZE]=select_batch_size()
                    return full_uc
                case settings.RUN_MODE.REALTIME:
                    return full_uc
                case _:
                    raise Exception("Runmode not valid!")
                
    def select_input_training(self) -> int | None:
        """
        Prompts the user to select an input for training detector.
        Returns use case number.
        """    
        print("\nBy default, the detector model will be trained using a default configuration provided in the default configuration file.") 
        change_input = input("Do you wish to use a different use case? (y/n): ").strip().lower()
        
        if change_input == 'y':
            interactive=input("Do you want to define a new use case? Otherwise you will be able to select one of the available use cases. (y/n):").strip().lower()
            if interactive == 'n':
                uc_n = input(f"Enter the number of the YAML configuration file (e.g., uc_1.yaml). The driver will look for YAML files in the drivers folder {settings.DRIVERS_FOLDER} :").strip()
            else:
                uc_dict=self.compile_uc_training()
                uc_n=add_new_uc(uc_dict)
            return int(uc_n)        
        elif change_input == 'n':
            uc_dict={}
            uc_dict[UC_TRAINING]={}  
            uc_n=add_new_uc(uc_dict)   
            return int(uc_n) 
        else:
            print(f"Invalid input!")

    def select_input_prediction(self) -> int | None:
        """
        Prompts the user to select an input for predicion.
        Returns use-case number.
        """    
        interactive=input("Do you want to define a new use-case?  Otherwise you will be able to select one of the avaliable use-cases. (y/n):").strip().lower()
        if interactive == 'n':
            uc_n = input(f"Enter the number of the YAML configuration file (e.g., uc_1.yaml). The driver will look for YAML files in the drivers folder {settings.DRIVERS_FOLDER} :").strip()
            return int(uc_n)
        elif interactive == 'y':
            uc_dict=self.compile_uc_prediction()
            uc_n=add_new_uc(uc_dict)
            return int(uc_n)    
        else:
            print(f"Invalid input!")     

def select_date():
    """
    Prompts the user to select a date for training.
    Returns the selected date in 'YYYY-MM-DD' format or 'default' based on user input.
    """ 
           
    while True:
        index_date = input("\nEnter the date in 'YYYY-MM-DD' format; an asterisk (*) is allowed at any position: ").strip()
        pattern = re.compile(r"^(?:\d{4}|\*)-(?:\d{2}|\*)-(?:\d{2}|\*)$")
        
        if pattern.match(index_date):
            return index_date
        else:
            print("Invalid date format!")

def select_name():
    """
    Prompts the user to select a name for the detector.
    Returns a name in the default format if no name is provided.
    """    
    if use_default(): return UC_DEFAULT
    print("\nBy default, the detector will be named in the format 'detector_<current timestamp>'.") 
    
    detector_name = input("Enter the name for the detector: ").strip()
    return detector_name

 

def use_default():
    d=input(f"Use default value?(y/n)").strip().lower()
    return d=='y'

def select_time(time:str):
    """
    Prompts the user to select a date for training.
    Returns the selected date in 'YYYY-MM-DDTHH:MM:SSZ' format or 'default' based on user input.
    """     
    pattern = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?$")

    while True:
        timestamp = input(f"Enter the {time} in 'YYYY-MM-DDTHH:MM:SSZ' format (e.g., 2024-07-09T00:00:00Z): ").strip()
        if pattern.match(timestamp): return timestamp


def select_run_mode():
    """
    Prompts the user to select a run mode and returns the corresponding mode string from an array.

    Returns:
        str: Selected run mode ('HISTORICAL', 'BATCH', 'REALTIME') or 'default' if no valid selection is made.
    """
    modes=settings.RUNMODE_LIST
    print(f"Select a run mode for prediction {modes}:")
    for i, mode in enumerate(modes, start=1):
        print(f"{i}. {mode}")

    while True:    
        selection = int(input("Enter the number corresponding to the selected run mode: "))
        if 0 < selection <= len(modes):
            return selection

def select_batch_size():
    """
    Prompts the user to enter a batch size and returns the entered batch size as an integer.

    Returns:
        int: Selected batch size entered by the user.
    """
    while True:
        try:
            batch_size = int(input("Enter the batch size (must be a positive integer): "))
            if batch_size > 0:
                return batch_size
            else:
                print("Batch size must be a positive integer! Please try again.")
        except ValueError:
            print("Invalid input! Please enter a valid number.")

def add_new_uc(di):
    # Regular expression for the pattern "uc_{n}.yaml"
    regex = re.compile(r"uc_(\d+)\.yaml")
    
    max_uc=0

    try:
        # Iterate through all items in the folder
        for filename in os.listdir(settings.DRIVERS_FOLDER):
            # Check if the filename matches the regex
            match = regex.fullmatch(filename)
            if match:
                # Extract the number from the filename
                n = int(match.group(1))
                # Append the filename and its corresponding integer to the list
                max_uc=max(max_uc,n)

    except Exception as e:
        print(f"An error occurred: {e}")

    with open(settings.UC_YAML_FILE.format(number=max_uc+1), 'w') as yaml_file:
            yaml.dump(di, yaml_file)

    return max_uc+1

def select_features() -> list[str]|str:
    """
    Prompts the user to select a list of feature for training.
    """     

    print(f"The list of avaliable feature is at {settings.WAZUH_COLUMNS_PATH}")
    with  open(settings.WAZUH_COLUMNS_PATH, 'r') as cols_file:
        cols=json.load(cols_file)

    cols_list=list(cols.get(UC_COLUMNS,{}).keys())

    feat=[]

    while True:
        new_col = input(f"Enter a feature: ").strip().lower()
        if new_col in cols_list: 
            feat.append(new_col)
        else: print("Invalid chioice.")
        more= input(f"Add a new feature? (y/n): ")
        if more != 'y': break 

    return feat 

def set_aggr()-> list:

    agg_methods=["average", "max", "min", "count", "sum"]
    f_agg=[]
    while len(f_agg)<1:
        for a in agg_methods:
            if input(f"Use {a}?(y/n)")=="y" : f_agg+=[a]
    return f_agg

def select_train_config()-> dict:
    tr={}
    tr[UC_EPOCHS]= int(input(f"Number of epochs? (int): "))
    tr[UC_WINDOW_SIZE]= int(input(f"Window size? (int): "))
    return tr

def select_granularity() -> str:
    return input('Granularity (e.g, "1min", "5min", "1s" "1hour"): ').strip()

if __name__ == "__main__":
    c=Console(False)
    c.main()
