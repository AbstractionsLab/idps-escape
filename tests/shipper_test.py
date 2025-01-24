import os
import unittest
from unittest.mock import patch

from siem_mtad_gat import settings
from siem_mtad_gat.shipper.wazuh_data_shipper import CREATE, DELETE, TemplateHandler, WazuhDataShipper
from siem_mtad_gat.shipper.wazuh_base_template import AD_BASE_TEMPLATE, AD_BASE_TEMPLATE_NAME, AD_DETECTOR_PATTERN, MAPPINGS, PROPERTIES, TEMPLATE, TYPE



TEST_ALG="this_is_test"
## Algorithm components
TEST_COMPONENT_NAME="component_template_"+TEST_ALG
TEST_COMPONENT= {
            TEMPLATE: 
                {MAPPINGS: 
                    {PROPERTIES: 
                        { "test_property": {
                                TYPE: "float"
                            }
            }}}}
TEST_MAP_ALG_COMPONENT={
TEST_ALG : (TEST_COMPONENT_NAME, TEST_COMPONENT)
}

class TestHandler(unittest.TestCase):
    def setUp(self):
        self.th=TemplateHandler()

    def test_base(self):
        self.assertEqual(AD_BASE_TEMPLATE,self.th.get_base_template())
    
    def test_comp(self):
        excomp={'template': {'mappings': {'properties': {0: {'type': 'float'}, 1: {'type': 'float'}, 2: {'type': 'int'}, 3: {'type': 'int'}}}}}
        a= range(4)
        b=2*["float"]+2*["int"]
        c=zip(a,b)
        self.assertEqual(self.th.get_detector_templ_component(c),excomp)
    
    def test_name(self):
        self.assertEqual(self.th.get_detector_stream_name("89"),AD_DETECTOR_PATTERN+"_89")

    def test_add(self):
        self.th.add_component("This is a compontent")

class TestShipperOnline(unittest.TestCase):
    def setUp(self):
        self.wds=WazuhDataShipper()
        self.connection=self.wds.test_connection()
        if self.connection: self.wds.install()
    
    def test(self):
        wds=self.wds
        if not self.connection: 
            print("Wazuh connection not avaliable")
            return
        # simple detector
        self.assertFalse( wds.client.indices.exists("adbox_detector_0")) # detector doesn't exists
        wds.create_detector_stream(detector_id='0',algorithm=None) 
        self.assertTrue( wds.client.indices.exists("adbox_detector_0")) # detector exists
        wds.delete_data_stream('0',algorithm=None)
        self.assertFalse( wds.client.indices.exists("adbox_detector_0"))# detector doesn't exists
        #with feature and algorithm
        #check template and component don't exist before 
        self.assertFalse(wds.index_template_exists("adbox_detector_mtad_gat_0"))
        self.assertFalse(wds.client.cluster.exists_component_template('component_template_0'))
        features=[("test0","float")]
        wds.create_detector_stream('0',features=features)
        self.assertTrue(wds.index_template_exists("adbox_detector_mtad_gat_0")) #template existsadbox_detector_mtad_gat_0
        self.assertTrue(wds.client.cluster.exists_component_template('component_template_0'))  #template component exists
        wds.delete_data_stream('0')
        #check template and component don't exist after
        self.assertFalse(wds.index_template_exists("adbox_detector_mtad_gat_0"))
        self.assertFalse(wds.client.cluster.exists_component_template('component_template_0'))
        
    def test_policy(self):
        wds=self.wds
        if not self.connection: 
            print("Wazuh connection not avaliable")
            return
        path:str= os.path.join(settings.TEST_ASSETS, 'test_policy.json')
        # check test policy not installed
        policies=wds.get_policies_list()
        self.assertFalse("test_policy_adbox" in policies)
        
        # install test policy
        wds.add_policy("test_policy_adbox",path)
        
        # check test policy is installed
        policies=wds.get_policies_list()
        self.assertTrue("test_policy_adbox" in policies)

        # install test policy
        wds.delete_policy("test_policy_adbox")  

        # check test policy not installed
        policies=wds.get_policies_list()
        self.assertFalse("test_policy_adbox" in policies)
    
    @patch('siem_mtad_gat.shipper.wazuh_data_shipper.MAP_ALG_COMPONENT',TEST_MAP_ALG_COMPONENT)
    def test_add_template_algorithm(self):
        wds=self.wds 
        template=AD_BASE_TEMPLATE_NAME+"_"+TEST_ALG
        self.assertFalse(wds.index_template_exists(template))
        wds.add_template_algorithm(TEST_ALG)
        self.assertTrue(wds.index_template_exists(template))        

        wds.client.indices.delete_index_template(template)
        wds.client.cluster.delete_component_template(TEST_COMPONENT_NAME)

    def test_bulk_request(self):
        wds=self.wds 
        out = """{"create": {"_index": "test_stream"}} 
{"0": 0} 
{"delete": {"_index": "test_stream"}} 
{"1": 1} 
{"create": {"_index": "test_stream"}} 
{"2": 2} 
{"delete": {"_index": "test_stream"}} 
{"3": 3}"""
        
        actions=2*[CREATE, DELETE]
        data=list(map(lambda x: {x:x},range(4) ))
        self.assertEqual(out,wds.get_bulk_request(data,"test_stream",actions))