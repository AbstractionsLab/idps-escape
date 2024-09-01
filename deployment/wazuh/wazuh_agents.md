
# Wazuh Agents 

Wazuh agents perform the primary HIDS step: monitoring.
Moreover, for IDPS-ESCAPE they play a central role in the integration of Wazuh and Suricata. 

The Wazuh agent is multi-platform and runs on the endpoints that the user wants to monitor. It communicates with the Wazuh server or manager, sending data in near real-time through an encrypted and authenticated channel. 

An agent **SHALL** be deployed on the central components host. Additionally, one can deploy an agent (connected to the central manager) on every other host to be monitored.
 
## Installation  

### Requirements
The installation of Wazuh agents require, Wazuh distribution to be running. 


### Installing a Wazuh Agent 
The Wazuh agent can be installed through the following two ways. 


1.  Using the Wazuh dashboard to deploy a new agent.
2.  Deploying Wazuh agents on Linux endpoints through CLI.   
      
    We provide details to setup an agent through both the ways.

#### 1\. Using the Wazuh dashboard to deploy a new agent 
To deploy a new agent on the Wazuh Dashboard, follow these steps:

1.  Navigate to Wazuh > Agents and click on Deploy new agent.
2.  Choose the appropriate package for your system, such as Linux DEB amd64.
3.  Specify the server address for the agent. This address is used for communication between the Wazuh agent and manager. If the agent and manager are on the same machine in a Docker installation, use the docker host address IP. Otherwise, use the IP address of the machine where the manager is deployed.
  To find the docker host address IP, run: 

	```sh 
	    sudo docker network inspect bridge | grep Gateway
	```
	alternatively,

	```sh
		ip addr show docker0 | grep -Po 'inet \K[\d.]+'
	```
4.  Optionally, provide a name for the agent.
5.  After entering the required information, download and install the agent using the provided command on the dashboard. For example:    
    ```sh
    wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.2-1_amd64.deb && sudo WAZUH_MANAGER='172.17.0.1' WAZUH_AGENT_NAME='test-agent' dpkg -i ./wazuh-agent_4.7.2-1_amd64.deb
    ``` 
6.  Finally, start the agent by executing the following commands:    
    ```sh
    sudo systemctl daemon-reload 
    sudo systemctl enable wazuh-agent
    sudo systemctl start wazuh-agent
    ```

And it can be seen that the agent is running. The status of the agent can be checked by: 
```sh
sudo systemctl status wazuh-agent
```

#### 2\. Deploying Wazuh agents on Linux endpoints through CLI

To enroll Wazuh agents via agent configuration, follow these steps for a Unix/Linux endpoint:

1.  Install the GPG key: 
	 ```sh
	sudo curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && sudo chmod 644 /usr/share/keyrings/wazuh.gpg 
	```
 
     
3.  Add the repository: 
	```sh
	echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee -a /etc/apt/sources.list.d/wazuh.list 
	```
    
4.  Update the package information:
       
	```sh 
	sudo apt-get update
	```
    
5.  Deploy a Wazuh agent:
    Select the appropriate package manager and set the `WAZUH_MANAGER` variable to include the IP address or hostname of the Wazuh manager. If the agent and manager are on the same machine in a Docker installation, use the docker host address IP. Otherwise, use the IP address of the machine where the manager is deployed.
    
	To find the docker host address IP, run:
        
		```sh
		  sudo docker network inspect bridge | grep Gateway` 
		``` 
	
	Or alternatively.
	
	```sh
		ip addr show docker0 | grep -Po 'inet \K[\d.]+'
	``` 
		
        
7.  Deploy the Wazuh agent with the following command:
	```sh
	WAZUH_MANAGER="172.17.0.1" WAZUH_AGENT_NAME="agent-on-host-machine" sudo apt-get install wazuh-agent
	 ```
    
8.  Enable and start the Wazuh agent service:
	   ```sh
	    sudo systemctl daemon-reload 
	    sudo systemctl enable wazuh-agent
	    sudo systemctl start wazuh-agent
	   ```

These steps will configure and deploy a Wazuh agent on the Unix/Linux endpoint, allowing it to communicate with the Wazuh manager for monitoring and security purposes. 
The status of the agent can be checked by: 
```sh
sudo systemctl status wazuh-agent
``` 



