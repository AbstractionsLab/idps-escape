import adbox.request_response_handler.keys as resp_keys

#KEYS
TYPE="type"
MAPPINGS="mappings"
PROPERTIES="properties"
COMPOSED_OF="composed_of"
TEMPLATE="template"
PRIORITY="priority"
INDEX_PATTERNS="index_patterns"
DATA_STREAM="data_stream"
NAME="name"
PATTERN="pattern"
# VALUES
TIMESTAMP="timestamp"

AD_BASE_TEMPLATE_NAME="adbox_stream_template"
AD_DETECTOR_PATTERN = "adbox_detector"
AD_INDEX_PATTERNS = [
    AD_DETECTOR_PATTERN+"_*",
    "adbox_prediction_*"
  ]

BASE_TEMPLATE_KEYS=[INDEX_PATTERNS,TEMPLATE,COMPOSED_OF,PRIORITY,"_meta",DATA_STREAM]#,NAME

AD_BASE_TEMPLATE={
  INDEX_PATTERNS: AD_INDEX_PATTERNS,
  TEMPLATE: {
    "settings": {
      "index.refresh_interval": "30s",
      "index.number_of_replicas": 0,
      "index.number_of_shards": 1,
    },
    MAPPINGS: {
      PROPERTIES: {
        resp_keys.IS_ANOMALY: {
          TYPE: "boolean"
        },
#        resp_keys.PREDICTION_VALUES: {
#          TYPE: "object",
#          PROPERTIES: {}
#        }
        }
        },
    "aliases": {}
  },
  COMPOSED_OF: [],
  PRIORITY: 1,
  "_meta": {
    "flow": "simple"
    },
  DATA_STREAM: {
    "timestamp_field": {
      "name": TIMESTAMP
      }
    },
  #NAME: AD_BASE_TEMPLATE_NAME
}


## Algorithm components
MTAD_GAT_COMPONENT_NAME="component_template_mtad_gat"
MTAD_GAT_COMPONENT= {
                      TEMPLATE: 
                          {MAPPINGS: 
                              {PROPERTIES: 
                                  { resp_keys.SCORE: {
                                        TYPE: "float"
                                      },
                                      resp_keys.THRESHOLD: {
                                        TYPE: "float"
                                      }
                      }}}}

FEATS_COMPONENT_NAME="component_template_{id}"

if __name__=="__main__":
    print(AD_BASE_TEMPLATE)