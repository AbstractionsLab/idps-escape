from datetime import datetime
from typing import List, Dict, Any, Tuple
from opensearchpy import OpenSearch
from siem_mtad_gat.data_ingestion.ad_data_ingestor import ADDataIngestor 
import siem_mtad_gat.settings as settings
from siem_mtad_gat.data_ingestion.wazuh.default_data_lookup import DefaultDataLookup 
import json 
import logging 
import os
os.makedirs(settings.OUTPUT_LOGS, exist_ok=True)
logging.basicConfig(filename=settings.LOGGING_FILE_NAME.format(name=__name__), format=settings.DEFAULT_LOGGING_FORMAT)
logger = logging.getLogger(__name__)
logger.setLevel(settings.DEFAULT_LOGGING_LEVEL) 

# Constants for dictionary keys
HOST_KEY = "host"
PORT_KEY = "port"
USERNAME_KEY = "username"
PASSWORD_KEY = "password" 
# Wazuh columns path 
WAZUH_COLUMNS = settings.WAZUH_COLUMNS_PATH

class WazuhDataIngestor(ADDataIngestor):
    """
    Data ingestor for retrieving SIEM alert data from Wazuh Indexer using OpenSearch.
    """

    def __init__(self, host: str = None, port: int = None, auth: tuple = None, use_ssl: bool = True,
                 verify_certs: bool = False, ssl_assert_hostname: bool = False,
                 ssl_show_warn: bool = False, ca_certs: str = None):
        """
        Initializes the WazuhDataIngestor with connection parameters.

        Args:
            host (str): Hostname of the OpenSearch server.
            port (int): Port of the OpenSearch server.
            auth (tuple): Authentication credentials (username, password).
            use_ssl (bool, optional): Whether to use SSL. Defaults to True.
            verify_certs (bool, optional): Whether to verify SSL certificates. Defaults to False.
            ssl_assert_hostname (bool, optional): Whether to assert SSL hostname. Defaults to False.
            ssl_show_warn (bool, optional): Whether to show SSL warnings. Defaults to False.
            ca_certs (str, optional): Path to CA certificates. Defaults to None.
        """
        #super().__init__()  # Call superclass initializer if ADDataIngestor has one
        
         # Check if any of the values are None
        if host is None or port is None or auth is None:
            # Read credentials from the JSON file
            with open(settings.WAZUH_CREDENTIALS_PATH, 'r') as json_file:
                credentials = json.load(json_file)

            logging.info("Wazuh data ingestor establishing connection to Wazuh...")

            # Access the credentials 
            host = credentials[HOST_KEY]
            port = credentials[PORT_KEY] 
            username = credentials[USERNAME_KEY]
            password = credentials[PASSWORD_KEY] 
            auth = (username, password)
        
                
        self.client = OpenSearch(
            hosts=[{'host': host, 'port': port}],
            http_compress=True,
            http_auth=auth,
            use_ssl=use_ssl,
            verify_certs=verify_certs,
            ssl_assert_hostname=ssl_assert_hostname,
            ssl_show_warn=ssl_show_warn,
            ca_certs=ca_certs
        )

    def get_training_data(self, date: str) -> Tuple[List[Dict[str, Any]], str]:
        """
        Retrieves SIEM alert data from Wazuh Indexer for a given date.

        Args:
            date (str): Date for which to retrieve SIEM alert data (format 'YYYY-MM-DD').
            columns (List[str]): List of columns to fetch from the index.

        Returns:
            List[Dict[str, Any]]: List of documents retrieved from the specified index.
            str : The index name of the data index 

        Raises:
            Exception: If an error occurs while retrieving SIEM alert data.
        """
        # Check connection with OpenSearch
        if not self.check_connection():
            print(
                "Could not establish a connection with OpenSearch.\n"
                f"More details logged in {settings.LOGGING_FILE_NAME.format(name=__name__)}"
            )
            logging.error("Error connecting to OpenSearch!") 
            logging.info("Fetching data from file. ") 
            default_data_lookup = DefaultDataLookup()
            all_documents, datasource_name =  default_data_lookup.get_default_train_data(date)
            return all_documents, datasource_name 
            
        else:    
            try:
                # Get index name for the given date
                index_name = self.get_index_name_for_date(date)

                # Check if the given index exists
                if not self.check_index_exists(index_name):
                    logging.error(f"The index '{index_name}' does not exist.")
                    print(f"The index '{index_name}' does not exist.")

                # Fetch the list of columns from the wazuh column config file 
                with open(WAZUH_COLUMNS, 'r') as file:
                    config_data = json.load(file) 
                    columns = list(config_data['columns'].keys())
                
                # Get all documents from the index
                all_documents = self.get_all_documents_paginated_from_index(index_name, columns)

                return all_documents, index_name 

            except Exception as e:
                logging.error(f"Error occurred while getting SIEM alert data: {e}")


    def get_prediction_data(self, date:str, start_time:str, end_time:str, run_mode=settings.RUN_MODE.HISTORICAL) -> Tuple[List[Dict[str, Any]], str]:
        """
        Retrieves SIEM alert data from Wazuh Indexer for a given date.

        Args:
            date (str): Date for which to retrieve SIEM alert data (format 'YYYY-MM-DD').
            columns (List[str]): List of columns to fetch from the index.

        Returns:
            List[Dict[str, Any]]: List of documents retrieved from the specified index.

        Raises:
            Exception: If an error occurs while retrieving SIEM alert data.
        """ 
        # Check connection with OpenSearch
        if not self.check_connection(): 
            if run_mode == settings.RUN_MODE.HISTORICAL: 
                print(
                    "Could not establish a connection with OpenSearch.\n"
                    f"More details logged in {settings.LOGGING_FILE_NAME.format(name=__name__)}"
                ) 
                logging.error("Error connecting to OpenSearch!") 
                logging.info("Fetching data from file. ") 
                default_data_lookup = DefaultDataLookup()
                all_documents =  default_data_lookup.get_default_predict_data(date)
                index_name = "default_predict_data"
                return all_documents  
            else: 
                print(
                    "Could not establish a connection with OpenSearch.\n"
                    f"More details logged in {settings.LOGGING_FILE_NAME.format(name=__name__)}\n"
                    f"Prediction in {run_mode} requires a connection with OpenSearch."
                ) 
                logging.error("Error connecting to OpenSearch!")
                return 
 
        #print(start_time, end_time)
        else: 
            try:
                # Get index name for the given date
                index_name = self.get_index_name_for_date(date)

                # Check if the given index exists
                if not self.check_index_exists(index_name):
                    logging.error(f"The index '{index_name}' does not exist.")
                    print(f"The index '{index_name}' does not exist.")

                # Fetch the list of columns from the wazuh column config file 
                with open(WAZUH_COLUMNS, 'r') as file:
                    config_data = json.load(file) 
                    columns = list(config_data['columns'].keys())
                
                # Get all documents from the index
                all_documents = self.get_all_documents_paginated_from_index_by_time_range(index_name, columns, start_time, end_time)

                return all_documents  

            except Exception as e: 
                logging.error(f"Error occurred while getting SIEM alert data: {e}")
                #raise Exception(f"Error occurred while getting SIEM alert data: {e}") 
        
        
        
    def check_connection(self) ->  bool:
        """
        Checks the connection to the OpenSearch cluster. 

        Returns:
            bool: True if the cluster status is "green" or "yellow", False otherwise.

        Raises:
            Exception: If an error occurs while checking the connection.
        """
        try:
            # Send a request to retrieve cluster health information
            response = self.client.cluster.health()

            # Check if the cluster status is "green" or "yellow"
            cluster_status = response.get("status")
            if cluster_status in ["green", "yellow"]:
                return True
            else:
                return False

        except Exception as e: 
            logging.error(f"Error occurred while checking connection: {e}")
            return False 
            #raise Exception(f"Error occurred while checking connection: {e}")

    def check_index_exists(self, index_name: str) -> bool:
        """
        Checks if the specified index exists.

        Args:
            index_name (str): Name of the index to check.

        Returns:
            bool: True if the index exists, False otherwise.

        Raises:
            Exception: If an error occurs while checking the index.
        """
        try:
            # Check if the index exists
            return self.client.indices.exists(index=index_name)

        except Exception as e:
            logging.error(f"Error occurred while checking index '{index_name}': {e}")

    def get_index_name_for_date(self, input_date: str) -> str:
        """
        Gets the index name for a given date.

        Args:
            input_date (str): Date to get the index name for (format 'YYYY-MM-DD' or '*').

        Returns:
            str: Index name for the given date, or None if the date format is invalid.

        Raises:
            ValueError: If the input_date format is invalid.
        """
        try:
            if '*' in input_date:
                year, month, day = input_date.split('-')
                year = '*' if year == '*' else year
                month = '*' if month == '*' else month
                day = '*' if day == '*' else day
                index_name = f"wazuh-alerts-*.*-{year}.{month}.{day}" 
                #index_name = f"wazuh-alerts-4.x-{year}.{month}.{day}"
                return index_name
            else:
                date_obj = datetime.strptime(input_date, settings.DATE_FORMAT)
                index_name = f"wazuh-alerts-*.*-{date_obj.year}.{date_obj.month:02d}.{date_obj.day:02d}" 
                #index_name = f"wazuh-alerts-4.x-{date_obj.year}.{date_obj.month:02d}.{date_obj.day:02d}"
                return index_name

        except ValueError:
            print("Error: Invalid date format. Please provide the date in the format 'YYYY-MM-DD'.")
            return None

    def get_all_documents_paginated_from_index(self, index_name: str, columns: List[str]) -> List[Dict[str, Any]]:
        """
        Retrieves all documents from the specified index using pagination.

        Args:
            index_name (str): Name of the index to retrieve documents from.
            columns (List[str]): List of columns to fetch from the index.

        Returns:
            List[Dict[str, Any]]: List of all documents in the index.

        Raises:
            Exception: If an error occurs while retrieving documents.
        """
        try:
            page_size = 10000  # Number of documents per page, 10000 is the maximum number that could be fetched in one request 
            all_documents = []

            # Add timestamp in the list of columns 
            
            # Retrieve documents using pagination
            while True:
                # Define search body with match_all query, sorting, and search_after
                search_body = {
                    "size": page_size,
                    "_source": columns,
                    "query": {"match_all": {}},
                    "sort": [{"timestamp": "asc"}]
                }

                if all_documents:
                    search_body["search_after"] = all_documents[-1]['sort']

                # Send request to retrieve documents
                response = self.client.search(index=index_name, body=search_body)

                # Check if response contains hits field
                if 'hits' in response and 'hits' in response['hits']:
                    hits = response['hits']['hits']
                    if not hits:
                        break  # No more documents to retrieve

                    all_documents.extend(hits)

                else:
                    logging.error("Hits field not found in response.")

            return all_documents

        except Exception as e:
            logging.error(f"Error occurred while retrieving all documents: {e}") 
        
        
        
    def get_all_documents_paginated_from_index_by_time_range(self, index_name: str, columns: List[str], start_time: str, end_time: str) -> List[Dict[str, Any]]:
        """
        Retrieves documents from the specified index within a given time range using pagination.

        Args:
            index_name (str): Name of the index to retrieve documents from.
            columns (List[str]): List of columns to fetch from the index.
            start_time (datetime): Start time for the time range.
            end_time (datetime): End time for the time range.

        Returns:
            List[Dict[str, Any]]: List of documents within the specified time range.

        Raises:
            Exception: If an error occurs while retrieving documents.
        """
        try:
            page_size = 10000  # Number of documents per page, 10000 is the maximum number that could be fetched in one request 
            all_documents = []

            # Add timestamp in the list of columns

            # Retrieve documents using pagination
            while True:
                # Define search body with range query, sorting, and search_after
                search_body = {
                    "size": page_size,
                    "_source": columns,
                    "query": {
                        "range": {
                            "timestamp": {
                                "gte": start_time, # start_time.isoformat(),
                                "lte": end_time, # end_time.isoformat(),
                                "format": "strict_date_optional_time||epoch_millis"
                            }
                        }
                    },
                    "sort": [{"timestamp": "asc"}]
                }

                if all_documents:
                    search_body["search_after"] = all_documents[-1]['sort']

                # Send request to retrieve documents
                response = self.client.search(index=index_name, body=search_body)

                # Check if response contains hits field
                if 'hits' in response and 'hits' in response['hits']:
                    hits = response['hits']['hits']
                    if not hits:
                        break  # No more documents to retrieve

                    all_documents.extend(hits)

                else:
                    logging.error("Hits field not found in response.")
            
            return all_documents

        except Exception as e:
            logging.error(f"Error occurred while retrieving all documents by time range: {e}")
