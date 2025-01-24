import json
import logging
import opensearchpy.exceptions 
from opensearchpy import OpenSearch
from siem_mtad_gat.commons import EscapeError, EscapeInfo, EscapeWarning,logger
from siem_mtad_gat.shipper import DataShipper
import siem_mtad_gat.settings as settings
import siem_mtad_gat.request_response_handler.keys as resp_keys
from siem_mtad_gat.shipper.wazuh_base_template import AD_BASE_TEMPLATE, AD_BASE_TEMPLATE_NAME, AD_DETECTOR_PATTERN, BASE_TEMPLATE_KEYS, COMPOSED_OF, FEATS_COMPONENT_NAME, INDEX_PATTERNS, MAPPINGS, MTAD_GAT_COMPONENT, MTAD_GAT_COMPONENT_NAME, NAME, PATTERN, PRIORITY, PROPERTIES, TEMPLATE, TYPE

logger = logging.getLogger(__name__)
logger.setLevel(settings.DEFAULT_LOGGING_LEVEL)

HOST_KEY = settings.OP_HOST_KEY
PORT_KEY = settings.OP_PORT_KEY
USERNAME_KEY = settings.OP_USERNAME_KEY
PASSWORD_KEY = settings.OP_PASSWORD_KEY

# TO-DO double check the following arguments (same as ingestor)
HTTP_COMPRESS=True
USE_SSL=True
VERIFY_CERTS=False
SSL_ASSERT_HOSTNAME=False
SSL_SHOW_WARN=False
CA_CERTS=None

#Bulk actions
CREATE="create"
DELETE="delete"
INDEX="index"
UPDATE="update"
SCRIPT="script"

MAP_ALG_COMPONENT={
    settings.MTAD_GAT : (MTAD_GAT_COMPONENT_NAME,MTAD_GAT_COMPONENT)
}

CONNECTION_MESSAGE="ADBox shipper connected to Wazuh"
ERROR_INSTALL_MESSAGE="ADBox shipper not installed!"


def get_template_name_and_patter_algorithm(algorithm):    
        template_name=AD_BASE_TEMPLATE_NAME+"_"+algorithm ## This is a convention please do not change!
        pattern=AD_DETECTOR_PATTERN+"_"+algorithm ## This is a convention please do not change!
        return template_name,pattern

#https://github.com/opensearch-project/opensearch-py/blob/main/guides/index_template.md
class TemplateHandler: 
    def __init__(self,pattern=AD_DETECTOR_PATTERN,name:str=AD_BASE_TEMPLATE_NAME):
        self.pattern = pattern
        self.name = name
        self.body={k: v for k,v in AD_BASE_TEMPLATE.items()} # use as body a (DEEP!) copy of the base template
        
        if not all([ x in self.body for x in BASE_TEMPLATE_KEYS]): raise EscapeError("Missing keys in selected base template")
        self.body[INDEX_PATTERNS]=[pattern+"_*"]
        #index_patterns=self.body.get(INDEX_PATTERNS,[])
        #if self.pattern+"_*" not in index_patterns: self.body[INDEX_PATTERNS].append(pattern+"_*") 
        
    @staticmethod
    def get_base_template():
        return AD_BASE_TEMPLATE
    
    @staticmethod
    def get_detector_templ_component(features):
        properties=dict()
        for x,y in features:
            properties[x]={TYPE:y} # does not support object type
        return {TEMPLATE: { MAPPINGS: {PROPERTIES: properties}}}

    def get_detector_stream_name(self,uuid):
        name = self.pattern+"_"+uuid
        return name

    def add_component(self,component_name):
        #don"t append to composed of otherwhise the base tamplate is modified!
        self.body[COMPOSED_OF]=self.body[COMPOSED_OF]+[component_name] #  remember to put this component before putting the index template in OpSearch!
        self.body[PRIORITY]+=1

    def set_pattern_as_detector_name(self,uuid):
        name = self.pattern+"_"+uuid
        self.body[INDEX_PATTERNS]=[name]
        return name



class WazuhDataShipper(DataShipper):
    def __init__(self, config:dict=dict(),install:bool=False):
        super().__init__(config)
        self.base_template_pattern = AD_DETECTOR_PATTERN
        self.map_alg_templates={}

        # Read credentials from the JSON file
        with open(settings.WAZUH_CREDENTIALS_PATH, "r") as json_file:
                credentials: dict = json.load(json_file)

        EscapeInfo("ADBox Shipper establishing connection to Wazuh...",logger)

        # Extract credential from config, as use same credential as for fetching
        host : str = config.get(HOST_KEY,credentials.get(HOST_KEY))
        port : int= config.get(PORT_KEY,credentials.get(PORT_KEY))
        username:str = config.get(USERNAME_KEY,credentials.get(USERNAME_KEY))
        password:str = config.get(PASSWORD_KEY,credentials.get(PASSWORD_KEY))
        auth = (username, password)
        
                
        self.client = OpenSearch(
            hosts=[{"host": host, "port": port}],
            http_compress=HTTP_COMPRESS,
            http_auth=auth,
            use_ssl=USE_SSL,
            verify_certs=VERIFY_CERTS,
            ssl_assert_hostname=SSL_ASSERT_HOSTNAME,
            ssl_show_warn=SSL_SHOW_WARN,
            ca_certs=CA_CERTS
        )

        if install: self.install()

    def test_connection(self):
        # Implementation of test_connection (same as ingestor)
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
            EscapeError(f"Error occurred while checking connection to: {e}",logger)
            return False 

    def index_template_exists(self,name:str):
        return self.client.indices.exists_index_template(name=name)
       
    def install(self,algorithms:list=settings.ML_ALGORITHMS_LIST):
        connection=self.test_connection()
        if connection:
            base_template_exists=self.index_template_exists(AD_BASE_TEMPLATE_NAME)
            if base_template_exists: EscapeInfo(CONNECTION_MESSAGE,logger)
            else:
                EscapeInfo(CONNECTION_MESSAGE,logger)
                base_template=TemplateHandler()
                response = self.client.indices.put_index_template( 
                                                    name=base_template.name,
                                                    body=base_template.body)
                EscapeInfo(response,logger)
            for alg in algorithms:
                self.add_template_algorithm(algorithm=alg)
                    
        else:
            raise EscapeError("Connection to Wazuh indexer not available: shipping impossible",logger)
        
        

    def ship_single(self, detector_stream:str, document:dict,):
        # Implementation of ship_single
        response = self.client.index(
            index = detector_stream,
            body = document
            )
        return response

    def ship_bulk(self, request):
        # Implementation of ship_bulk
        return self.client.bulk(request)

    def get_single_request(self, data:dict, detector_stream:str):
        # Implementation of get_single_request
        pass
        
    def get_bulk_request(self, data, detector_stream:str,actions:list[str]):
        #{ "create" : { "_index" : "my-dsl-index", "_id" : "3" } } 
        li=zip(actions,data)
        bulk=''
        for action,doc in li:
             a={action : {"_index" : detector_stream}}
             bulk= bulk + json.dumps(a)+' \n'+json.dumps(doc)+' \n'
        
        bulk=bulk[:-2]
        return bulk

    def add_template_algorithm(self, algorithm:str|None):
        
        if algorithm in self.map_alg_templates.keys():
            return
        if algorithm is None:
            return
        template_name,pattern=get_template_name_and_patter_algorithm(algorithm)
        if self.index_template_exists(template_name):
            self.map_alg_templates[algorithm]={}
            self.map_alg_templates[algorithm][NAME]=template_name
            self.map_alg_templates[algorithm][PATTERN]=pattern
            EscapeInfo(f"Template for {algorithm} initialized",logger)
            return
        else:               
            new_template=TemplateHandler(pattern=pattern,name=template_name) # create a template
            try:
                name,body=MAP_ALG_COMPONENT.get(algorithm) # type: ignore
            except:
                raise EscapeError("Algorithm component not defined!",logger)
            self.client.cluster.put_component_template(name=name, body=body)
            new_template.add_component(component_name=name) # add algorithm to base template
            response = self.client.indices.put_index_template( 
                                                    name=new_template.name,
                                                    body=new_template.body)
            EscapeInfo(response)
            self.map_alg_templates[algorithm]={}
            self.map_alg_templates[algorithm][NAME]=template_name
            self.map_alg_templates[algorithm][PATTERN]=pattern
            EscapeInfo(f"Template for {algorithm} initialized",logger)
            return
     
    def create_template_handler_from_base(self, components:list,algorithm:str|None=None) -> TemplateHandler:
        """
        Create an instance of TemplateHandler that can be used to put a new template 
        Attention this method puts the component in the indexer!
        
        Args. 
            components (list): index template components proper of the detection algorithm every element of the list must be
                    a pair whose first element is the name of the component and the second is the body. 

        """

        if algorithm is not None: 
            components=[MAP_ALG_COMPONENT.get(algorithm)]+components
            template_name,pattern=get_template_name_and_patter_algorithm(algorithm)
            new_template=TemplateHandler(pattern=pattern,name=template_name)
        else: 
            new_template=TemplateHandler(self.base_template_pattern) # create a template
        for name,body in components:
            self.client.cluster.put_component_template(name=name, body=body)
            new_template.add_component(name) # add components from detection algorithm

        return new_template

    def create_detector_stream(self, detector_id:str,
                               algorithm:str|None=settings.MTAD_GAT,
                               features:list|None=None):
        """Creating a detector stream

        Args:
            detector_id(str): Detector's uuid. 
            algorithm (str): name of the algorithm used in detector
            features (None | list[tuple[str, str]], optional): A list of properties to create a template component. 
                                                            Every property is a tuple containing a feature name (str) and 
                                                            the type (str). Defaults to None.

        Returns:
            The OpenSearch client response.

        Example:
            features = [("Feat_1_score", "float"), ("Threshold+1", "float")]
        """
        uuid=detector_id#detector_info.get(resp_keys.DETECTOR_ID)
        if features is not None:
            component_feat=TemplateHandler.get_detector_templ_component(features=features)# create a features' component
            component_feat_name=FEATS_COMPONENT_NAME.format(id=uuid)
            new_template: TemplateHandler=self.create_template_handler_from_base(components=[(component_feat_name,component_feat)],algorithm=algorithm) # create a new template handler
            detector_stream=new_template.set_pattern_as_detector_name(uuid) # set stream name
            response = self.client.indices.put_index_template( 
                                                name=detector_stream,
                                                body=new_template.body) #create stream
        else:
            self.add_template_algorithm(algorithm)
            pattern=self.map_alg_templates[algorithm].get(PATTERN) if algorithm is not None else AD_DETECTOR_PATTERN
            detector_stream=TemplateHandler(pattern=pattern).get_detector_stream_name(uuid) # set stream name
            response = self.client.indices.create_data_stream(detector_stream) #create stream
        return response,detector_stream       

    def put_algorithm_template_component(self,name:str,body:dict):
        self.client.cluster.put_component_template(name=name,body=body)
    
    def update_template(self, template):
        # Private method to update template
        pass

    def check_status(self, detector_id):
        # Private method to check the status of a detector
        pass

    def delete_data_stream(self, detector_id,algorithm:str|None=settings.MTAD_GAT):
        # Implementation for deleting a data stream
        
        if algorithm is None: 
            th=TemplateHandler()
        else:   
            try:
                base_alg=self.map_alg_templates.get(algorithm)
                name=base_alg.get(NAME)
                patt=base_alg.get(PATTERN)
            except:
                raise EscapeError("Algorithm not initialized!",logger)
            th=TemplateHandler(pattern=patt,name=name)
        streamname=th.get_detector_stream_name(detector_id)
        self.client.indices.delete_data_stream(streamname)
        EscapeInfo(f"Removed {streamname}",logger)
        try:
            component_list=self.client.indices.get_index_template(streamname).get("index_templates")[0].get("index_template").get("composed_of")
            self.client.indices.delete_index_template(streamname)
            for c in component_list: 
                if c!= MAP_ALG_COMPONENT.get(algorithm,("",""))[0]: self.client.cluster.delete_component_template(c)
        except:
            EscapeInfo("Attempt to remove template: either missing custom template or wrong pattern matching",logger)

    def delete_doc(self, detector, doc_id):
        # Implementation for deleting a document
        response = self.client.delete(
            index = detector,
            id = doc_id
            )
        return response

    def update_doc(self):
        # Implementation for updating a document
        pass

    def add_clean_policy(self):
        # Implementation for adding a clean-up policy
        pass

    def add_policy(self,policy_name:str,body_path:str):
        # add policy
        # Read policy from the JSON file
        with open(body_path, "r") as json_file:
            policy_content: dict = json.load(json_file)
            return self.client.index_management.put_policy(policy_name, body=policy_content)

    def add_rollover_policy(self):
        # add rollover policy
        try:
            policy_name:str="adbox_detectors_rollover"
            body_path:str=settings.POLICY_ROLLOVER
            response = self.add_policy(policy_name,body_path)
            EscapeInfo(f"Rollover policy {policy_name} created.")
        except opensearchpy.exceptions.ConflictError as e:
            logger.warning(e)
            print(f"Policy {policy_name} already exists.")
    
    def get_policy(self,name=None,nice_print:bool=True):       
        # returns policy body, if input is None returns all policies available
        try:
            response=self.client.index_management.get_policy(name)
            return json.dumps(response, indent=2) if nice_print else response
        except opensearchpy.exceptions.NotFoundError:
             EscapeInfo("Policy not found.")
             return
    
    def get_policies_list(self):       
        # returns policy body, if input is None returns all policies available
        response:dict=self.get_policy(nice_print=False)
        policies=[p.get("_id") for p in response.get("policies",[])]
        np= response.get("total_policies")
        assert len(policies)==np, "error fetching policies' list"
        return policies

    def update_policy(self):
        raise NotImplementedError("Sorry! The policy update is not yet avaliable via OpenSearch client, please use either ISM API or Dashboard, directly.")
    
    def delete_policy(self,policy_name):
        response = self.client.index_management.delete_policy(policy_name)
        EscapeInfo(response)

    def check_install(self):
        connection=self.test_connection()
        if connection:
            base_template_exists=self.index_template_exists(AD_BASE_TEMPLATE_NAME)
            if base_template_exists: EscapeInfo(CONNECTION_MESSAGE,logger)
            else:
                raise EscapeError(ERROR_INSTALL_MESSAGE,logger)          
        else:
            raise EscapeError("Connection to Wazuh indexer not available: shipping impossible",logger)
