# Integration modules

In this folder, we store all artifacts required for enabling our integration 
solutions, ranging from integration with well-known TIPs such as MISP and 
OpenCTI, to custom CTI tools, and fixes to other publicly available solutions 
incorporated into IDPS-ESCAPE. Below we provide a concise map of the currently available integration possibilities.

We also provide analyses of these integrations in terms of their benefits 
for automating flows from alerts and events to CTI platform level views.

## Automated enrichment workflows for improved CTI

The [automated trigger](/integrations/opencti-wazuh-connector/automated_trigger/README.md) stored at [integrations/opencti-wazuh-connector/automated_trigger](/integrations/opencti-wazuh-connector/automated_trigger/) provides

- scripts to query OpenCTI for enrichment requests for every Observable.
- to enable automated enrichment of Cyber Threat Intelligence from SIEM observations.

## Resolved timestamp parsing issue in OpenCTI-Wazuh connector

Our modified version of the [OpenCTI-Wazuh connector](/integrations/opencti-wazuh-connector/README.md) stored at [integrations/opencti-wazuh-connector](/integrations/opencti-wazuh-connector/) provides

- a fix applied to the timestamp parsing of CTI data between Wazuh and OpenCTI;
- a query fix dealing with email fields;
- ultimately, enabling a smooth integration between OpenCTI and Wazuh.