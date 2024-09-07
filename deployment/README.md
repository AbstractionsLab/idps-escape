# Instructions for IDPS and SIEM integrated deployment

IDPS-ESCAPE, short for Intrusion Detection and Prevention Systems for Evading Supply Chain Attacks and Post-compromise Effects, focuses on developing a sophisticated Security Information and Event Management (SIEM) system tailored for cloud-edge networks. This solution includes agents capable of seamless installation on systems earmarked for monitoring, along with a cutting-edge Intrusion Detection and Prevention System (IDPS) infused with machine learning capabilities. 

This folder explains the integration of Suricata, an open-source Intrusion Detection System (IDS) renowned for its robust network security capabilities, and Wazuh, a cybersecurity platform that integrates SIEM and XDR capabilities, which play a crucial role in enhancing the capabilities of the IDPS-ESCAPE solution and are the  building blocks for the IDPS-ESCAPE prototype.


**Folder Structure:**

-   **[Suricata Installation Process:](./suricata/)** The Suricata installation process can be found in the suricata folder within this repository. Detailed instructions for installing Suricata are provided along with the necessary configuration steps and required artifacts.
    
-   **[Wazuh Installation Process:](./wazuh/)** Similarly, the Wazuh installation process is documented in the wazuh folder. Follow the instructions provided to install Wazuh and configure it according to your requirements. The folder contains the installation process for Wazuh distribution and Wazuh agents. 

-   **[Remote monitoring procedure:](./remote_monitoring/)** The remote_monitoring folder contains the configuration files and guidelines for enabling this setup to monitor remote machines in the network. 

## Integration Procedure 
Once Suricata and Wazuh are installed, proceed with the integration process outlined in this readme file. This integration aims to enhance the capabilities of intrusion detection and threat hunting within the environment, facilitating centralized management and monitoring of security incidents and events across multiple hosts. 
 

### Requirements 
1. [A running instance of the Suricata service](./suricata/suricata_installation.md)
2. [A running instance of the Wazuh distribution](./wazuh/wazuh_installation.md)
3. [An installation of a Wazuh agent](./wazuh/wazuh_agents.md)

### Using Docker Volumes to integrate Suricata and Wazuh 

Docker volumes facilitate data sharing between containers, allowing multiple containers to access the same data simultaneously. By creating a volume on the host machine, we can store Suricata logs for the Wazuh agent to access. Through Docker volumes, we establish a connection between the Suricata container's log directory and a directory on the host machine where the Wazuh agent operates. To set up the volume for the log files, we update the run command with the -v argument, specifying the paths for data exchange between the containers and the host machine. The modified command incorporating the -v argument for volumes and the respective paths ensures seamless data communication between the Suricata container and the Wazuh agent. 

The command to build the container remains the same. 
```sh 
sudo docker build -t suricata-container . 
``` 
And the command to run the container is modified as following. 

```sh 
sudo docker run -v /var/log/suricata:/var/log/suricata --network=host --hostname=suricata-instance --name=suricata-instance -d suricata-container
```


To enable the Wazuh agent to access Suricata log files, the configuration file of the Wazuh agent needs to be modified.  The configuration file is present at `/var/ossec/etc/ossec.conf` on the machine where the agent was installed. Open the configuration file with any text editor and add the following lines at the end of the file, before the &lt;/ossec\_config&gt; closing tag with the path of the mounted volume.

```sh
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/eve.json</location>
  </localfile>
</ossec_config>
```

Restart the agent and then the logs could be seen on the Wazuh dashboard.

```sh
sudo systemctl restart wazuh-agent 
```
To test the correct working of the integration, any online tool that generates some malicious traffic for testing purposes can be used, such as: 

[GitHub - 3CORESec/testmynids.org: A website and framework for testing NIDS detection](https://github.com/3CORESec/testmynids.org)  
