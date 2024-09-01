import threading
import siem_mtad_gat.settings as settings
from siem_mtad_gat.mtad_gat_pytorch.spot import SPOT
from siem_mtad_gat.data_manager.data_storage_manager import DataStorageManager
from siem_mtad_gat.data_manager.data_retrieval_manager import DataRetrievalManager

class SPOTManager:
    """
    SPOTManager class to handle SPOT persistent object.
    Assuming DataStorageManage instance existing.
    """
    
    # Semaphore to prevent concurrent access to the sensitive resource
    _semaphore = threading.Semaphore()

    # Singleton instance
    _instance = None

    def __new__(cls, *args, **kwargs):
        """
        Ensure only one instance of SPOTManager exists (Singleton Pattern).
        """ 
        if cls._instance is None: 
            if args:  
                cls._instance = super(SPOTManager, cls).__new__(cls) 
                cls._instance._initialize(args[0]) 
            else:             
                cls._instance = super(SPOTManager, cls).__new__(cls) 
                cls._instance._initialize()
        return cls._instance 
    

    def _initialize(self, n_features:int,q:float=0.001,load_obj:bool=False): 
        """
        Initialize the SPOTManager.
        """          
        self.init_q=q
        self.n_features=n_features
        self.files_ext='pkl'
    
        if load_obj:
            self.spot_list=self._load_all()
        else:
            #add a spot object for each feature plus global
            self.spot_list=[self._add_spot() for i in range(n_features+1)]
        
        assert len(self.spot_list)==(self.n_features+1)

    def _add_spot(self):
        return SPOT(self.init_q)
    

    def _load(self, feature:int=-1): #-1 is global
        data_storage_manager = DataStorageManager()
        data_retrieval_manager = DataRetrievalManager(data_storage_manager.uuid)
        if self.files_ext=="pkl":
            return data_retrieval_manager.load_spot(feature)
        elif self.files_ext=="json":
            # if in json we must initialise the object, sicne only args are stored
            spot_args = data_retrieval_manager.load_spot(feature)
            s=self._add_spot()
            s.proba=spot_args.get("proba")
            s.extreme_quantile=spot_args.get("extreme_quantile")
            s.data=spot_args.get("data")
            s.init_data=spot_args.get("init_data")
            s.init_threshold=spot_args.get("init_threshold")
            s.peaks=spot_args.get("peaks")
            s.n=spot_args.get("n")
            s.Nt=spot_args.get("Nt")

    def _load_all(self): 
        return [self._load(i) for i in range(self.n_features)]+[self._load(-1)]
            


    def save_all_train(self):
        data_storage_manager = DataStorageManager()
        for i in range(-1,self.n_features):
            data_storage_manager.save_spot_train(self.spot_list[i],i,self.files_ext)  
    

    @classmethod
    def destroy_instance(cls):
        cls._instance = None

        
        
           
        

