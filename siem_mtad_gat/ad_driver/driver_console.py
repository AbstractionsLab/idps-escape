from siem_mtad_gat.ad_engine.mtad_gat.ad_engine import ADEngine
import re
from tabulate import tabulate

# TO-REDESIGN (redesign and implement as robust use case scenario creation/modification tool and adbox inspector with input validation)

def main():
    """
    Runs an interactive loop allowing the user to invoke methods from the AD engine to ingest data, train detectors and run predictions.
    """
    engine = ADEngine() 
    
    while True: 
        print("\nEnter a number and press enter to select an ADBox action to perform:")
        print("1. Train an anomaly detector")
        print("2. Predict anomalies using the trained detector")
        print("3. Select an existing anomaly detector for prediction")
        print("4. Exit")
        
        action = input("Enter a number (1-4): ").strip()
        
        if action == '1': 
            index_date = select_date("train") 
            detector_name = select_name() 
            is_default, file_name = select_input()
            train_response= engine.train(index_date=index_date, detector_name=detector_name, default_config=is_default, custom_config_file=file_name)
            print("Training response: ", train_response)

        elif action == '2': 
            detector_id = select_detector(engine) 
            if detector_id == None: 
                continue 
            run_mode = select_run_mode()
            if run_mode == "HISTORICAL" or  run_mode == "default": 
                index_date = select_date("predict") 
                start_time = select_time("start")
                end_time = select_time("end")
                predict_response = engine.predict(index_date=index_date, run_mode=run_mode, detector_id=detector_id, start_time=start_time, end_time=end_time)
                for res in predict_response:
                    print("Prediction response: ", res)
                
            elif run_mode == 'BATCH': 
                batch_size = select_batch_size()
                predict_response = engine.predict(detector_id=detector_id, run_mode=run_mode, batch_size=batch_size)
                for res in predict_response:
                    print("Prediction response: ", res) 
                        
            elif run_mode == 'REALTIME': 
                predict_response = engine.predict(detector_id=detector_id, run_mode=run_mode)  
                for res in predict_response:
                    print("Prediction response: ", res) 

        elif action == '3': 
            select_detector(engine) 
            
        elif action == '4':
            print("Exiting the program...")
            break
        else:
            print("Invalid choice! Please try again.")



def select_date(caller:str=None):
    """
    Prompts the user to select a date for training.
    Returns the selected date in 'YYYY-MM-DD' format or 'default' based on user input.
    """ 
    if caller == "train": 
        print("\nBy default, the detector will be trained on data from the current month.")
    elif caller == "predict":
        print("\nBy default, the prediction will be run for today's data.")
            
    change_date = input("Change the date? (y/n): ").strip().lower()
    
    if change_date == 'y':
        while True:
            index_date = input("\nEnter the date in 'YYYY-MM-DD' format; an asterisk (*) is allowed at any position: ").strip()
            pattern = re.compile(r"^(?:\d{4}|\*)-(?:\d{2}|\*)-(?:\d{2}|\*)$")
            
            if pattern.match(index_date):
                return index_date
            else:
                print("Invalid date format! Please enter the date in 'YYYY-MM-DD' format or use '*' as needed.")
    
    elif change_date == 'n':
        return "default"
    
    else:
        print("Invalid input! using the default date.")
        return "default"

def select_name():
    """
    Prompts the user to select a name for the detector.
    Returns a name in the default format if no name is provided.
    """    
    print("\nBy default, the detector will be named in the format 'detector_<current timestamp>'.") 
    
    change_name = input("Provide a name for the detector? (y/n): ").strip().lower()
    
    if change_name == 'y':
        detector_name = input("Enter the name for the detector: ").strip()
        if detector_name:
            return detector_name
        else:
            print(f"No name provided! a default name will be used. ")
            return "default"

    elif change_name == 'n':
        return "default" 
    else:
        print(f"Invalid input! A default name will be used. ")
        return "default" 
 
 
 
def select_input():
    """
    Prompts the user to select an input for the detector.
    Returns a boolean specifying the choice and the configuration.
    """    
    print("\nBy default, the detector model will be trained using a default configuration provided in the default configuration file.") 
    change_input = input("Do you wish to use a different or modified YAML configuration file as input? (y/n): ").strip().lower()
    
    if change_input == 'y': 
        is_default = False 
        file_name = input("Enter the name of the YAML configuration file (e.g., driver). The driver will look for YAML files in the drivers folder (./siem_mtad_gat/assets/drivers/) :").strip() 
        return is_default, file_name 
    elif change_input == 'n': 
        return True, None 
    else:
        print(f"Invalid input! Default input will be used. ")
        return True, None  
 

def select_detector(engine:ADEngine):
        """
        Prompts the user to select a detector ID from the list of available detectors.
        
        Returns:
            str: Selected detector ID.
        """ 
        if engine.current_detector_id is None:
            print("No trained detectors found! train a detector before prediction or selection. ") 
            return 
        else:
            print(f"\nThe current detector ID is: {engine.current_detector_id}") 
            print("\nBy default, all predictions will be done using this detector.") 
            change_detector = input("Do you wish to change the detector used for prediction? (y/n): ").strip().lower()
        
            if change_detector == 'y':
                print("\nSelect a detector among the following list of available detectors:") 
                detectors = engine.get_detectors()
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
                            engine.select(selected_id) 
                            print(f"\nThe current detector ID is: {engine.current_detector_id}")  
                            return selected_id
                        else:
                            print("Invalid selection! The default detector will be used.") 
                            return "default" 
                    except ValueError:
                        print("Invalid input! Please enter a number.") 

            elif change_detector == 'n':
                return "default" 
            else:
                print(f"Invalid input! The default detector will be used. ")
                return "default" 
 

def select_time(time:str):
    """
    Prompts the user to select a date for training.
    Returns the selected date in 'YYYY-MM-DDTHH:MM:SSZ' format or 'default' based on user input.
    """ 
    if time == "start": 
        print("\nBy default, the start time for prediction will be the starting timestamp of today's date.")
    elif time == "end":
        print("\nBy default, the end time for prediction will be the current timestamp.")
    else: 
        raise ValueError("Invalid input") 
        
    change_time = input("Change the time? (y/n): ").strip().lower()
    
    if change_time == 'y':
        while True: 
            timestamp = input("\nEnter the timestamp in 'YYYY-MM-DDTHH:MM:SSZ' format (e.g., 2024-07-09T00:00:00Z): ").strip()
            pattern = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?$")
            
            if pattern.match(timestamp):
                return timestamp
            else:
                print("Invalid timestamp format! Please enter the timestamp in 'YYYY-MM-DDTHH:MM:SSZ' format.")
    
    elif change_time == 'n':
        return "default" 
    else:
        print(f"Invalid input! Default values will be used. ")
        return "default"  
    


def select_run_mode():
    """
    Prompts the user to select a run mode and returns the corresponding mode string from an array.

    Returns:
        str: Selected run mode ('HISTORICAL', 'BATCH', 'REALTIME') or 'default' if no valid selection is made.
    """
    modes = ['HISTORICAL', 'BATCH', 'REALTIME']
    
    print("Select a run mode for prediction:")
    for i, mode in enumerate(modes, start=1):
        print(f"{i}. {mode}")
    
    try:
        selection = int(input("Enter the number corresponding to the selected run mode: ")) - 1
        if 0 <= selection < len(modes):
            return modes[selection]
        else:
            print("Invalid selection! Defaulting to 'HISTORICAL'.")
            return 'default'
    
    except ValueError:
        print("Invalid input! Defaulting to 'HISTORICAL'.")
        return 'default'

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


if __name__ == "__main__":
    main()