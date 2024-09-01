import siem_mtad_gat.settings as settings
from datetime import datetime
import json 
import logging 
import os
os.makedirs(settings.OUTPUT_LOGS, exist_ok=True)
logging.basicConfig(filename=settings.LOGGING_FILE_NAME.format(name=__name__), format=settings.DEFAULT_LOGGING_FORMAT)
logger = logging.getLogger(__name__)
logger.setLevel(settings.DEFAULT_LOGGING_LEVEL)  


class DefaultDataLookup:
    """
    A class to handle default data lookups for training and prediction purposes.

    Methods
    -------
    get_default_train_data(date: str) -> dict
        Fetches the default training data for a given date.
        
    get_default_predict_data(date: str) -> dict
        Fetches the default prediction data for a given date.
    """

    def __init__(self):
        """
        Initializes the default_data_lookup class.
        """
        # Initialize any required attributes here
        # Directory where the data files are stored
        self.train_data_directory = settings.TRAIN_DATA_FOLDER  
        self.predict_data_directory = settings.PREDICT_DATA_FOLDER 
        self.train_data_file = settings.DEFAULT_TRAIN_DATA
        self.predict_data_file = settings.DEFAULT_PREDICT_DATA
        
        # Regex patterns to match the filenames

    def get_default_train_data(self, input_date: str):
        """
        Fetches the default training data for a given date.

        Parameters
        ----------
        date : str
            The date for which to fetch the training data in YYYY-MM-DD format.

        Returns
        -------
        dict
            A dictionary containing the default training data.
        """
        year, month, day = self.get_date_components(input_date)
        file_path = self.train_data_file.format(year=year, month=month) 
        
        all_documents = []
        
        if os.path.isfile(file_path):
             # Read train data from the JSON file 
            try: 
                with open(file_path, 'r') as json_file:
                    train_data = json.load(json_file) 
                    
                # Check if train_data contains hits field
                if 'hits' in train_data and 'hits' in train_data['hits']:
                    hits = train_data['hits']['hits']
                    all_documents.extend(hits)

                else:
                    logging.error("Hits field not found in train_data.")
                    
                print(f"Returning data from file {file_path} ")
                train_file_name = os.path.basename(file_path)
                return all_documents, train_file_name 
            
            except Exception as e:
                logging.error(f"Error occurred while retrieving default file: {e}")  
            
        else:
            print(f"The file '{file_path}' does not exist, returning all default data. ")
            # List all files in the directory
            for file_name in os.listdir(self.train_data_directory):
                file_path = os.path.join(self.train_data_directory, file_name)

                # Only process JSON files
                if os.path.isfile(file_path) and file_name.endswith('.json'):
                    try:
                        with open(file_path, 'r') as json_file:
                            train_data = json.load(json_file)
                            
                            # Check if train_data contains hits field
                            if 'hits' in train_data and 'hits' in train_data['hits']:
                                hits = train_data['hits']['hits']
                                all_documents.extend(hits)
                            else:
                                logging.error(f"Hits field not found in {file_name}.")
                    except Exception as e:
                        logging.error(f"Error processing file {file_name}: {e}")

            return all_documents, "sample-alerts-train"
       
            
        

    def get_default_predict_data(self, input_date: str) -> dict:
        """
        Fetches the default prediction data for a given date.

        Parameters
        ----------
        date : str
            The date for which to fetch the prediction data in YYYY-MM-DD format.

        Returns
        -------
        dict
            A dictionary containing the default prediction data.
        """ 
        year, month, day = self.get_date_components(input_date)
        file_path = self.predict_data_file.format(year=year, month=month, day=day)  

        all_documents = []

        
        if os.path.isfile(file_path):
             # Read predict data from the JSON file 
            try: 
                with open(file_path, 'r') as json_file:
                    train_data = json.load(json_file) 
                    
                # Check if train_data contains hits field
                if 'hits' in train_data and 'hits' in train_data['hits']:
                    hits = train_data['hits']['hits']
                    all_documents.extend(hits)

                else:
                    logging.error("Hits field not found in train_data.")
                    
                print(f"Returning data from file {file_path} ")
                return all_documents
            
            except Exception as e:
                logging.error(f"Error occurred while retrieving default file: {e}")  
            
        else:
            print(f"The file '{file_path}' does not exist, returning all default data. ")
            # List all files in the directory
            for file_name in os.listdir(self.predict_data_directory):
                file_path = os.path.join(self.predict_data_directory, file_name)

                # Only process JSON files
                if os.path.isfile(file_path) and file_name.endswith('.json'):
                    try:
                        with open(file_path, 'r') as json_file:
                            train_data = json.load(json_file)
                            
                            # Check if train_data contains hits field
                            if 'hits' in train_data and 'hits' in train_data['hits']:
                                hits = train_data['hits']['hits']
                                all_documents.extend(hits)
                            else:
                                logging.error(f"Hits field not found in {file_name}.")
                    except Exception as e:
                        logging.error(f"Error processing file {file_name}: {e}")

            return all_documents
 
    
    def get_date_components(self, input_date: str):
        try:
            if '*' in input_date:
                year, month, day = input_date.split('-')
                year = '*' if year == '*' else year
                month = '*' if month == '*' else month
                day = '*' if day == '*' else day
            else:
                date_obj = datetime.strptime(input_date, settings.DATE_FORMAT)
                year = date_obj.year
                month = f"{date_obj.month:02d}" 
                day = f"{date_obj.day:02d}"   
            return year, month, day
        except ValueError:
            print("Error: Invalid date format. Please provide the date in the format 'YYYY-MM-DD'.")
            return None, None, None 
        
        