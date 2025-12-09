# Getting started: IDPS and SIEM integrated deployment

# Automated full stack deployment

If you wish to make use of our integrated and fully automated full stack deployment, see our [guide](../../soar-radar/README.md) on making use the of the `build-radar.sh` script to bootstrap the IDPS-ESCAPE for RADAR via Ansible.

# Step-by-step artifact integration

Note that if you already have a running instance of Wazuh, and do not wish to integrate Suricata, you can simply skip to the [ADBox installation section](#adbox-installation).

A complete and installation of the signature-based intrusion detection and the SIEM subsystems of IDPS-ESCAPE can be done using the following guides:

1. Suricata, to enable network monitoring capabilities:

      a.  [installation in a containerized environment](./deployment/suricata/suricata_installation.md#installation-and-configuration-of-suricata)
      
      b.  [configuration to local network](./deployment/suricata/suricata_installation.md#suricata-configuration-file)
1. Wazuh central components installation, for SIEM \& XDR:

    a. [installation of Dashboard, Manager and Indexer in a containerized environment ](./deployment/wazuh/wazuh_installation.md)

    b. [configuration to local system](./deployment/wazuh/wazuh_installation.md#next-steps)

1. [Installation of a Wazuh agent](./deployment/wazuh/wazuh_agents.md) to enable host monitoring capabilities.

    a. Possibly, deployment of additional agents on other remote hosts (system *endpoints*), same as above.
  
    b. Possibly, [enable remote traffic monitoring](./deployment/remote_monitoring/remote_monitoring.md).

1. Follow [integration procedure of Suricata and Wazuh](./deployment/integration.md).

 Details of the above steps and scripts are provided in the [Guide for IDPS and SIEM integrated deployment](./deployment/README.md).

 This integration guarantees:
 
 - joint monitoring of host and network events, and
 - centralized storage.

All the data ending up in the central SIEM \& XDR can now be fed to ADBox for training ML models and anomaly detection, providing a holistic view of the system(s) under monitoring.