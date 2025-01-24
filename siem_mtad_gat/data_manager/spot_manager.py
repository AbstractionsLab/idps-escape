import logging
import threading
from siem_mtad_gat.commons import EscapeError, EscapeInfo, EscapeWarning

from siem_mtad_gat.data_manager  import *


from siem_mtad_gat.mtad_gat_pytorch.spot import SPOT
from siem_mtad_gat.data_manager.data_storage_manager import DataStorageManager
from siem_mtad_gat.data_manager.data_retrieval_manager import DataRetrievalManager



SPOT_REQ_MSG0="SPOT object requires features number"
SPOT_REQ_MSG1="Empty features' lists!"
SPOT_REQ_MSG2="n_features is None! Missine n_feature key arguments"
SPOT_REQ_MSG="SPOTManager assumes DataStorage object exists"
SPOT_ERR_EXT_MSG="Invalid file extension for loading SPOT"

class SPOTManager:
    """
    SPOTManager class to handle SPOT persistent object.
    Assuming DataStorageManager instance existing.
    """
    
    # Semaphore to prevent concurrent access to the sensitive resource
    _semaphore = threading.Semaphore()

    # Singleton instance
    _instance = None

    def __new__(cls, **kwargs):
        """
        Ensure only one instance of SPOTManager exists (Singleton Pattern).
        """ 
        if cls._instance is None:
            cls._instance = super(SPOTManager, cls).__new__(cls) 
            cls._instance._initialize(**kwargs)       
        return cls._instance 
    

    def _initialize(self, n_features:int|None=None,q:float=0.001,load_obj:bool=False,caller=settings.CALLER_TRAIN):  
        """
        Initialize the SPOTManager.
        """

        
        if DataStorageManager._instance is None:
            raise EscapeError(SPOT_REQ_MSG,logger)
            #raise Exception(SPOT_REQ_MSG)
        
        if n_features is None:
            raise EscapeError(SPOT_REQ_MSG2,logger)

        
        if n_features==0:
            #logging.warning(SPOT_REQ_MSG1)
            raise EscapeWarning(SPOT_REQ_MSG1)

        self.init_q: float=q
        self.n_features: int=n_features
        self.files_ext='pkl'
    
        if load_obj:
            if caller not in [settings.CALLER_OFFLINE,settings.CALLER_ONLINE]: raise EscapeError(f"To load SPOT objects caller must be either '{settings.CALLER_OFFLINE}' or '{settings.CALLER_ONLINE}'.")
            self.spot_list: list[SPOT]=self._load_all(caller=caller)
            EscapeInfo(f"SPOT list objects loaded, caller is {caller}",logger)
        else:
            #add a spot object for each feature plus global
            self.spot_list=[self._add_spot(self.init_q) for i in range(n_features+1)]
            EscapeInfo("SPOT list objects created",logger)


    def _add_spot(self,q) -> SPOT:
        """Add empty spot object instance"""
        return SPOT(q)
    

    def _load(self, feature:int=-1,caller:str=settings.CALLER_TRAIN)-> SPOT : # #-1 is global
        """
        Load SPOT object from file
        
        Args. 
            feature (int): feature number. If -1, takes global distribution.
        
        Returns.
            SPOT: spot instance for requested feature
        """
        data_storage_manager = DataStorageManager()
        data_retrieval_manager = DataRetrievalManager(data_storage_manager.uuid)
        if self.files_ext=="pkl":
            s : SPOT=  data_retrieval_manager.load_spot_pkl(feature,caller=caller)
            return s
        elif self.files_ext=="json":
            # if in json we must initialise the object, since only args are stored
            spot_args: dict = data_retrieval_manager.load_spot_json(feature,caller=caller)
            q= spot_args.get("proba")
            s: SPOT = self._add_spot(q)
            s.extreme_quantile=spot_args.get("extreme_quantile")
            s.data=spot_args.get("data")
            s.init_data=spot_args.get("init_data")
            s.init_threshold=spot_args.get("init_threshold")
            s.peaks=spot_args.get("peaks")
            s.n=spot_args.get("n")
            s.Nt=spot_args.get("Nt")
            return s
        else:
            raise EscapeError(SPOT_ERR_EXT_MSG,logger)


    def _load_all(self,caller) -> list[SPOT]: 
        """
        Loads all spot instances 
    
        Returns:
            list[SPOT]

        """
        return [self._load(i,caller) for i in range(self.n_features)]+[self._load(-1,caller)]
            

    def save_all_train(self):
        """Store in memory the all spot training objects"""
        data_storage_manager = DataStorageManager()
        for i in range(-1,self.n_features):
            data_storage_manager.save_spot(self.spot_list[i],i,self.files_ext,caller=settings.CALLER_TRAIN)  

    def save_online(self):
        """Store in memory the all spot objects for online"""
        data_storage_manager = DataStorageManager()
        for i in range(-1,self.n_features):
            data_storage_manager.save_spot(self.spot_list[i],i,self.files_ext,caller=settings.CALLER_ONLINE)          
    

    @classmethod
    def destroy_instance(cls):
        cls._instance = None

        
        
           
        

