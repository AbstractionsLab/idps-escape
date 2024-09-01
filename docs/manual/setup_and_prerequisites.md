# Setup and prerequisites 

## Setup

The installation guide includes the process of installing ADBox through different mechanisms. However, for the correct functioning of ADBox, some prerequisites need to be met. The repository comes with a set of configuration files bundled in the assets folder which need to be configured as per requirements. 

### ADBox configuration files 

In the repository cloned from GitHub, the assets folder is located at the following location w.r.t the root folder `./siem_mtad_gat/assets`.

The asset folder contains the following sub-folders:

- `data `
- `default_configs `
- `detector_models` 
- `drivers` 
- `secrets` 
- `wazuh` 

Below we explain the purpose for files in each folder and how they should be configured as per user requirements. 

1. **data:** The data folder contains two sub-folders, `predict` and `train` and each of them contain default data which can be used for training and prediction if there is no connection established with Wazuh i.e., no instance of Wazuh distribution is running. 
2. **default_configs:** This folder contains two files. `default_detector_input_config.json` which contains a default detector configuration. These are the values which the detector would be trained on by default. This file is not advised to be changed. The second file is `mtad_gat_train_config_default_args.json` which contains the default machine learning level model specifications for the training pipeline. By default, the machine learning model will be trained using these parameters. This file is also not advised to be changed. 
   **Note: These files should not be modified.**
3. **detector models:** This folder stores outputs from both training and prediction processes. Each trained model is uniquely identified by an ID, and all resulting data for each model is organized into folders named after their respective IDs. Then these folders contains sub folders and files which would be explained individually in the sections detailing training and prediction. 
4. **drivers:** This folder contains yaml files. These yaml files can be written and used for non-default training inputs. This folder contains a dummy `driver.yaml` file which explains the structure of these configuration files. Each time you set the default configuration option False and provide a yaml file name, ADBox tries to find it in this folder. The file should contain key names same as specified in the dummy file. And for every missing key or value, it will take values from the `default_detector_input_config.json` file. 
5. **secrets:** This folder contains `wazuh_credentials.json` file. Since ADBox fetches data from a SIEM i.e., Wazuh, it is required to have a running distribution of Wazuh along with a Wazuh agent deployed on the targeted machine which communicates with the Wazuh server and sends data in near real-time. These agents could also ship data from a network IDPS i.e., Suricata to the Wazuh server. 
6. **wazuh:** This folder contains `wazuh_columns.json` file. This json file contains a column dictionary which represents all the fields that ADBox  fetches from Wazuh and the datatype in which they are converted to since Wazuh treats all values as keywords. This file is also advised not to be modified. 

### SIEM and IDPS installations 

The ADBox uses a SIEM to fetch data, which should be integrated with a signature based IDPS. The installation process all the mentioned components can be followed from the following links. 

1. [Installation of Suricata](../../deployment/suricata/suricata_installation.md)
2. [Installation of Wazuh distribution](../../deployment/wazuh/wazuh_installation.md)
3. [Installation of Wazuh agent](../../deployment/wazuh//wazuh_agents.md)
4. [Integration of Wazuh with Suricata](../../deployment/README.md)
	
Once all the above requirements are fulfilled, the credentials to connect to the Wazuh distribution can be provided in the `wazuh_credentials.json` file in this folder. 
The json file contains 4 keys, whose values should be as following: 

- `"host"`: IP address of the machine on which Wazuh is deployed. 
- `"port"`: Wazuh indexer RESTful API's. By default, it is 9200 if not changed. 
- `"username"`: Username for the Wazuh dashboard, by default it is "admin". 
- `"password"`: Password for the Wazuh dashboard, by default it is "SecretPassword". 

ADBox will use these credentials to connect to Wazuh distribution and retrieve data from Wazuh alert indices for training and prediction.  

### Prerequisites

- Set the Wazuh credentials in the `./siem_mtad_gat/assets/secrets/wazuh_credentials.json` file. If not set or if ADBox is not able to form a connection with the Wazuh API, then it will use the default data stored in the repository and will only run in HISTORICAL detection mode. For BATCH and REALTIME mode, it is mandatory to set these values.  
  