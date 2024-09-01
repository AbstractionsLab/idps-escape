import pandas as pd

class ADDataIngestor: 
    def get_training_data(self, date: str, columns: list) -> pd.DataFrame:
        """
        Abstract method for getting training data.
        Subclasses should implement their own logic.
        """
        raise NotImplementedError("Subclasses must implement get_training_data method.")
    
    def get_prediction_data(self, date: str, columns: list) -> pd.DataFrame:
        """
        Abstract method for getting prediction data.
        Subclasses should implement their own logic.
        """
        raise NotImplementedError("Subclasses must implement get_prediction_data method.")