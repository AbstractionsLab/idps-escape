# RADAR test framework

## **1. Introduction**

The increasing complexity and scale of modern cyber threats necessitate advanced, automated security solutions that not only detect anomalies but also respond in real time. In this context, the SOAR-RADAR framework (Security Orchestration, Automation, and Response – Risk-Aware Detection-based Active Response) was developed as a modular and extensible testbed for simulating and evaluating anomaly detection capabilities in Security Information and Event Management (SIEM) systems.

This document presents the design and implementation of the **RADAR Test Framework**, a structured and automated evaluation environment built around Wazuh’s anomaly detection capabilities. The framework is designed to support **multiple threat scenarios**, simulating adversarial behavior and measuring detection effectiveness in realistic settings. Specifically, the system evaluates the performance of Wazuh's anomaly detection in identifying:

- **Insider Threats**: Malicious or negligent activities by authorized users.
- **Suspicious Logins**: Unauthorized or anomalous authentication attempts in Single Sign-On (SSO) environments.
- **Distributed Denial-of-Service (DDoS)** Attacks: Sudden surges in traffic aimed at exhausting system resources.
- **Malware Communication**: Covert communication with external command-and-control (C2) servers, typically through beaconing behavior.

Each of these scenarios is implemented as an isolated module following a consistent operational pipeline consisting of four key phases:

1. **Ingest**: Preparation of the dataset and injection into Wazuh/OpenSearch. In certain cases, this includes provisioning external components such as user identities in Keycloak (e.g., for login anomaly detection).
2. **Setup**: Automated deployment of system configurations including log collection rules, detection pipelines, and webhook integration. This is accomplished using Ansible scripts applied to a containerized environment or an external infrastructure.
3. **Simulate**: Execution of scenario-specific attack behaviors through scripted interactions with the system, mimicking real-world threat vectors and user actions.
4. **Evaluate**: Analysis of detection outputs by comparing actual events against labeled ground truth. Metrics such as True Positives (TP), False Positives (FP), False Negatives (FN), and True Negatives (TN) are computed to quantify system performance.

A central configuration file (`config.yaml`) provides modular control over the framework, allowing users to override parameters such as dataset location, OpenSearch indices, hostnames, thresholds, and attack intensity. This makes the framework adaptable to both research and production-oriented security setups.

The entire pipeline is orchestrated through a unified Python script (`mainctl.py`), which sequentially executes all phases while maintaining isolation between scenarios. The system architecture is containerized using `docker-compose`, supporting easy deployment and teardown, but it can be extended to work with remote hosts or cloud environments by adapting the Ansible configurations.

### Dependencies

> **Note**: Please remember to populate the [wazuh_indexer_ssl_certs](/radar/radar-test-framework/config/wazuh_indexer_ssl_certs/) with the required SSL certificates, which can be generated using the built-in [Wazuh certificates deployment script](https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/certificates.html).

## **2. Project Architecture**

The RADAR Test Framework is designed as a modular, containerized, and scenario-driven environment that facilitates the end-to-end lifecycle of anomaly detection research — from data ingestion and system setup, to attack simulation and evaluation. This architecture emphasizes automation, reproducibility, and extensibility, making it suitable for both experimental research and prototyping in real-world security environments.

### **2.1 High-Level Architecture Overview**

The framework operates across four main components:

1. **Wazuh Manager**: Collects and analyzes security logs, hosts the anomaly detection module, and triggers alerts or responses.
2. **Wazuh Agent**: Deployed on endpoints to collect logs and forward them to the manager.
3. **OpenSearch**: Stores ingested data and anomaly detection results for querying and evaluation.
4. **Supporting Components**:
    - **Keycloak** (for the Suspicious Login scenario): Acts as the identity provider, simulating real-world SSO login activity.
    - **Webhook Server**: Captures active response alerts from Wazuh.

Each component runs inside its own Docker container and is orchestrated using `docker-compose`. Communication between containers occurs over a shared virtual bridge network defined in the `docker-compose.yml`.

### **2.2 Containerized Environment via Docker Compose**

The `docker/docker-compose.yml` file defines the multi-container environment. Key services include:

- `wazuh.manager`: Hosts the Wazuh Manager, exposing ports for REST API, agent communication, and Kibana UI.
- `wazuh.indexer`: Runs OpenSearch to persist log and detection data.
- `wazuh.dashboard`: Provides Kibana-based UI to visualize logs and detection outputs.
- `wazuh.agent`: Simulated endpoint agent for log generation and attack simulation.
- `keycloak`: Identity provider (used in Suspicious Login scenario) with custom realm and users created during ingest.
- `webhook-server`: Python Flask service listening for Wazuh alerts, used for active response triggering and metric validation.

The containers mount relevant configuration directories (`ossec.conf`, rules, and anomaly detector configs) and allow persistent volumes for OpenSearch indices.

---

### **2.3 Logical Architecture by Phase**

### **Ingest Phase**

- Datasets (e.g., access logs, process usage) are read from CSV/JSON files and ingested into OpenSearch using the REST API.
- Each scenario is associated with a unique index (e.g., `wazuh-ad-insider-threat-*`).
- For Suspicious Login, user accounts and roles are automatically provisioned into Keycloak using its admin REST interface.

### **Setup Phase**

- Ansible is used to push configuration files (`ossec.conf`, ruleset additions, etc.) into Wazuh manager and agent containers.
- It also creates anomaly **detectors**, **monitors**, and **webhooks** in OpenSearch via API calls.
- If a non-Dockerized deployment is used, the Ansible inventory (`ansible/hosts`) can be modified to target remote systems via SSH.

### **Simulate Phase**

- Custom scenario scripts (e.g., `simulate/insider_threat_simulator.py`) trigger predefined user behaviors or network actions inside the agent container to emulate malicious or suspicious activity.
- Simulations are aligned with real-world tactics, such as privilege abuse, login anomaly, beaconing, and packet flooding.

> **Note:** The attack simulation phase for DDoS Detection, Malware Communication and Suspicious Login is currently not working due to ongoing development. This feature will be restored in a future update.

### **Evaluate Phase**

- Ground-truth labels are matched against anomalies detected by Wazuh.
- Results (TP, FP, TN, FN) are computed and written to CSV for analysis.
- This step relies on querying the result index of the anomaly detector and matching timestamps, user actions, or IPs.

---

### **2.4 Orchestration via `mainctl.py`**

The entire lifecycle (ingest → setup → simulate → evaluate) is orchestrated via a central control script, `mainctl.py`. This script:

- Loads `config.yaml` to determine scenario parameters, index names, host IPs, and run toggles.
- Invokes each module (ingest/setup/simulate/evaluate) sequentially using standardized APIs.
- Enables flexibility to run specific phases only (e.g., just simulate and evaluate, skipping ingestion).

---

### **2.5 Flexibility and Adaptability**

The architecture supports both:

- **Research environments**: Fully containerized, reproducible setups for repeatable experiments.
- **Operational environments**: Adaptable to remote or hybrid deployments using Ansible and external server IPs.

Furthermore, the modular design ensures that:

- New scenarios can be added by creating corresponding folders and scripts.
- Additional phases (e.g., retraining, threat intelligence correlation) can be introduced.
- Alternate log sources or SIEMs could be integrated by replacing the ingest and evaluate modules.

## **3. Configuration & Flexibility**

A key design objective of the RADAR Test Framework is **configurability and adaptability**. The framework must accommodate different use cases, datasets, deployment environments, and threat models. This is achieved through the central configuration file `config.yaml`, along with a flexible orchestration and automation layer that allows users to easily adapt the framework to their infrastructure and experimentation needs.

---

### **3.1 Central Role of `config.yaml`**

The `config.yaml` file defines the core configuration logic of the framework and acts as the runtime blueprint for scenario-specific detection settings. It is structured to allow the orchestration logic (`mainctl.py`) to dynamically load scenario metadata, anomaly detection parameters, and feature extraction settings for any selected anomaly type.

At the top level, the file includes:

- **`default_scenario`**: The scenario that will be executed by default if no override is provided at runtime.

```yaml
default_scenario: insider_threat
```

- **`scenarios`**: A hierarchical mapping of scenario names to their respective configuration blocks. Each block provides full details necessary for dataset loading, detection configuration, simulation, and evaluation. The four currently supported scenarios are:
    - `insider_threat`
    - `ddos_detection`
    - `malware_communication`
    - `suspicious_login`

Each scenario block includes the following fields:

### **General Metadata**

- `container_name`: The name of the container that will run the simulation for the scenario.
- `index_prefix`: OpenSearch index pattern used to store ingested data.
- `result_index`: OpenSearch index where the anomaly detection plugin will store results.
- `log_index_pattern` (optional): Pattern for log indices, used during query and evaluation (present in some scenarios).
- `dataset_dir` or `label_csv_path`: Directory or CSV file path for the labeled dataset used in evaluation.

### **Detection Engine Parameters**

- `time_field`: The field in the document that represents the event timestamp (e.g., `"@timestamp"`).
- `categorical_field`: The primary dimension used to segment the data (e.g., `user.keyword`, `Destination_IP.keyword`).
- `detector_interval`: How often the anomaly detector runs (in minutes).
- `delay_minutes`: Optional delay between data ingestion and anomaly detection to allow for buffering.

### **Alerting Configuration**

- `monitor_name`: Name of the monitor created in OpenSearch.
- `trigger_name`: Name of the trigger that fires when an anomaly is detected.
- `anomaly_grade_threshold`: Minimum anomaly grade (0.0 to 1.0) for triggering alerts.
- `confidence_threshold`: Minimum confidence score required to consider the result valid.

### **Feature Engineering**

Each scenario defines a list of `features`, where each feature block contains:

- `feature_name`: A semantic label used for reference.
- `feature_enabled`: Boolean flag to include/exclude the feature in the detection pipeline.
- `aggregation_query`: Defines how the feature is computed using OpenSearch aggregations (e.g., sum, average, cardinality).

Each scenario has between 3 to 5 carefully selected features. These features are tailored to the specific anomaly behavior being modeled

---

### **3.2 Handling Pre-Ingested Data**

One of the most important capabilities is the support for **pre-ingested datasets**. If users have already indexed their data into OpenSearch (e.g., for longitudinal testing or A/B comparisons), they can bypass the `ingest` phase by:

1. Defining the correct `index_prefix` to point to their existing dataset.

This flexibility decouples the evaluation logic from the dataset ingestion pipeline and encourages reuse of long-running or curated datasets.

---

### **3.3 Environment Agnosticism**

While the default deployment uses Docker and Docker Compose for simplicity and isolation, the framework is designed to support external or hybrid environments.

This is made possible through:

- **Ansible-based setup**: All configuration push operations (e.g., Wazuh’s `ossec.conf`, agent registration, rule updates) are abstracted via roles and playbooks in the `ansible` folder.
- **Inventory abstraction**: The file `ansible/hosts` can be updated to reflect real server IPs, credentials, and SSH configuration. No code changes are needed to target a live cluster.
- **Keycloak provisioning**: The Suspicious Login scenario includes automatic user creation in Keycloak via API, which is also environment-independent, relying only on valid credentials and reachable endpoints.

> Note: In live environments, certain volumes or ports (e.g., `/var/ossec`, `tcp/55000`) must be exposed or routed accordingly.
> 

---

### **3.4 Extensibility for New Scenarios**

The configuration system is **scenario-agnostic**. To add a new scenario:

1. Add a new scenario section in `config.yaml` (e.g., `ransomware_outbreak:`).
2. Create a folder structure under `/simulate`, `/evaluate`, `/ingest` (optional).
3. Implement the corresponding logic using the same interface (e.g., class-based script with `run()` method).
4. Optionally define detection index and thresholds.

This structure allows modular plug-and-play development for new use cases without modifying the orchestration logic.

---

### **3.5 Runtime Control via CLI**

While `config.yaml` controls the default flow, the `mainctl.py` script supports runtime overrides for:

- Selecting specific scenarios (`-scenario insider_threat`)
- Running a single phase (`-phase simulate`)
- Running all phases for a scenario (`-phase all`)

## **4. Ingest Phase**

The **Ingest Phase** is the first operational step in the RADAR Test Framework pipeline. Its primary goal is to prepare the system for anomaly detection by injecting synthetic or pre-collected datasets into the OpenSearch backend, and by optionally provisioning external components (e.g., user accounts in Keycloak for authentication-based scenarios).

This phase is executed using Python classes tailored to each scenario, and it is automatically invoked by the `mainctl.py` controller. Alternatively, it can be skipped when using pre-ingested datasets, as discussed in Section 3.

---

### **4.1 General Responsibilities**

The ingest modules handle the following core responsibilities:

- **Indexing labeled datasets** into OpenSearch under scenario-specific indices (e.g., `wazuh-ad-insider-threat-*`).
- Ensuring that timestamps, categorical keys, and other fields conform to the expected format for the anomaly detection module.
- Triggering external system preparation steps when necessary (e.g., provisioning users for the Suspicious Login scenario).

---

### **4.2 Scenario-Specific Ingest Logic**

Each scenario has its own implementation under the the scenario folder with a script `wazuh_ingest.py`. The ingest logic is scenario-aware and utilizes both OpenSearch and third-party APIs.

### **Insider Threat**

- Reads a labeled CSV file (`file*.csv`) containing simulated user activity: file access, content volume, and number of distinct files accessed.
- Extracts and transforms relevant fields (`user`, `filename`, `content_bytes`, etc.).
- Inserts each row into OpenSearch under the index prefix `wazuh-ad-insider-threat-*`.

### **DDoS Detection**

- Loads a CSV dataset (`Syn.csv`) representing network flow records: source/destination IPs, port numbers, flags, and traffic rates.
- Fields include: `Flow_Packets_s`, `Flow_Bytes_s`, `SYN_Flag_Count`, and others.
- Indexed into OpenSearch under the prefix `wazuh-ad-ddos-detection-*`.

### **Malware Communication**

- Reads structured CSV logs from the Bro/Zeek network monitoring tool (in `dataset_dir`).
- Contains connection-level details such as `id.orig_h`, `id.resp_h`, `orig_bytes`, `resp_bytes`, etc.
- Documents are ingested into the `wazuh-ad-malware-c2-*` index, which is used later by both the detector and evaluation module.

### **Suspicious Login**

- Read logs in CSV format from RBA dataset with fields such as `User ID`, `Country`, `event_hour`, etc.
- Indexed into the `wazuh-ad-suspicious-login-*` index.
- Additionally, this phase **interacts with a Keycloak instance** running in Docker to provision users. It uses Keycloak’s admin API to:
    - Create users specified in the dataset.
    - Assign them appropriate roles or groups.
    - Emulate a real authentication backend for detection and evaluation purposes.

---

### **4.4 OpenSearch Ingestion Method**

In all scenarios, ingestion is implemented via OpenSearch’s `_bulk` API to ensure efficient indexing of large datasets. The code:

- Batches records into chunks (e.g., 500–1000 entries).
- Structures each entry as a JSON document aligned to the detector’s schema.
- Automatically creates the index if it doesn’t exist.
- Adds scenario-specific metadata such as user ID, IP, file name, or login location.

This approach ensures the ingest phase is efficient, repeatable, and compatible with OpenSearch’s anomaly detection plugin.

## **5. Setup Phase**

The **Setup Phase** is responsible for configuring the detection environment, including Wazuh agents and managers, log collection rules, and the anomaly detection infrastructure in OpenSearch. This phase ensures that all necessary components are initialized and synchronized before the attack simulations begin. It is designed to be **fully automated** using **Ansible**, with built-in support for both containerized and non-containerized deployments.

The setup logic is modularized and scenario-aware. It reads configuration values from `config.yaml` and applies them consistently across Wazuh, OpenSearch, and related components.

---

### **5.1 Core Responsibilities**

The Setup Phase performs the following main tasks:

1. **Copying configuration files** (`ossec.conf`, rules, decoders) to Wazuh manager and agent containers or remote servers.
2. **Restarting services** to apply the updated configuration.
3. **Registering agents** with the Wazuh manager (if not already registered).
4. **Creating anomaly detectors** in OpenSearch for each scenario.
5. **Defining monitors and triggers** that continuously evaluate incoming data for anomalies.
6. **Registering webhook receivers** to enable active response on detection.

---

### **5.2 Configuration Deployment via Ansible**

The framework uses **Ansible** to automate the configuration and deployment process. The `ansible/` directory contains the following components:

- `site.yml`: The master playbook executed for setup.
- `hosts`: Inventory file that defines the target machines or containers.
- `roles/`: Ansible roles for `wazuh_manager` and `wazuh_agent`.

Each role performs scenario-specific setup, including:

- Uploading the appropriate `ossec.conf` file.
- Copying rule files, decoders, or active response scripts.
- Executing `wazuh-control restart` inside the target container to reload the configuration.

> ⚙️ Docker vs SSH:
> 
> 
> By default, the inventory targets containers such as `agent.insider` or `wazuh-manager`. For remote deployments, users can modify the `hosts` file to specify IP addresses and SSH credentials of external servers. This allows seamless transition from testing to production environments.
> 

---

### **5.3 Detector Creation in OpenSearch**

Each scenario's setup includes **creating a custom anomaly detector** in OpenSearch using the REST API. This detector is configured based on the parameters defined in `config.yaml`:

- **Input index**: Derived from the `index_prefix` (e.g., `wazuh-ad-insider-threat-*`).
- **Time field**: Usually `@timestamp`, defining the time axis for aggregation.
- **Categorical field**: Allows profiling behavior per user/IP/etc.
- **Detector interval**: How often the detector runs (in minutes).
- **Feature list**: Extracted from `features` defined in the config file.

The setup module constructs and submits a detector creation request using this structure and stores the `detector_id` for later reference during evaluation.

---

### **5.4 Monitor and Trigger Registration**

Once the detector is created, the system automatically registers:

- A **monitor**, which periodically queries the anomaly detection results.
- A **trigger**, which defines conditions (e.g., anomaly grade > 0.8 AND confidence > 0.85) to raise an alert.

Example configuration (for `insider_threat`):

- Monitor name: `InsiderThreat-Monitor`
- Trigger name: `Insider-Threat-Detected`
- Trigger condition:
    
    ```json
    if (anomaly_grade >= 0.6) AND (confidence >= 0.7)
    ```
    

These monitors and triggers ensure continuous evaluation of detection logic and form the basis for active response escalation.

---

### **5.5 Webhook Receiver Setup**

The Setup Phase also ensures that Wazuh’s active response mechanism can communicate with the webhook server running in a container. The process involves:

- Registering a **webhook destination** via the OpenSearch API.
- Linking this destination to the monitor trigger.
- Ensuring the webhook server (Flask API) is running and listening on the appropriate port.

Webhook alerts are later consumed during the **Evaluate Phase** to determine whether detections occurred and whether they met the defined thresholds.

---

### **5.6 Restart and Validation**

Finally, the setup logic performs a restart of relevant services to apply the new configurations. This includes:

- Restarting the Wazuh manager (`wazuh-control restart`)
- Restarting the agent container(s) if needed
- Verifying agent registration status via the Wazuh API
- Ensuring detectors appear in OpenSearch and are in a running state

---

### **5.7 Extensibility Considerations**

The setup phase is fully extensible:

- New rules or decoders can be added by modifying the `roles/wazuh_manager` files.
- Custom detectors can be defined by extending the `setup/` Python module.
- External destinations (e.g., Slack, email) can be configured alongside webhook.

## **6. Simulate Phase**

The **Simulate Phase** plays a critical role in the RADAR Test Framework by generating realistic, scenario-specific behavioral data. It emulates threat behavior within the Wazuh agent container, enabling Wazuh and the anomaly detection pipeline to detect deviations from normal activity. This phase ensures that synthetic but realistic threat signals are produced under controlled conditions.

Each simulation script is scenario-specific and is designed to:

- Mimic real-world behavior patterns aligned with threat models.
- Execute directly inside or against the Wazuh agent container.
- Ensure that logs are produced in the correct format and with relevant metadata fields.

The simulation logic is structured as independent Python classes, each with a `run()` method invoked by the `mainctl.py` orchestration controller.

---

### **6.1 Insider Threat Simulation**

This script emulates abnormal file access behavior by a user, such as:

- Reading large volumes of data,
- Accessing a high number of distinct files,
- Repeating the same actions multiple times.

**Implementation Highlights**:

- Randomly selects a list of users and filenames.
- Reads log entries from the agent container.
- Supports a `repeat_count` to simulate multiple iterations of the same behavior, mimicking persistence or repeated internal data exfiltration attempts.
- Injects logs into the Wazuh index.

---

### **6.2 DDoS Detection Simulation**

This script simulates a **SYN flood**-style DDoS attack using repeated packet flow events. Each record imitates a single TCP flow targeting the server.

**Implementation Highlights**:

- Fields generated include: `Source_IP`, `Destination_IP`, `Flow_Packets_s`, `SYN_Flag_Count`, `Total_Backward_Packets`.
- Utilizes `random` generation to simulate traffic bursts across multiple source IPs.
- Logs are written line-by-line into Wazuh index.
- Delays are inserted between batches to simulate sustained attacks over time.

---

### **6.3 Malware Communication Simulation**

This module simulates beaconing behavior, a common trait of malware communicating with external command-and-control (C2) servers.

**Implementation Highlights**:

- Each record contains: `uid`, `id.orig_h`, `id.resp_h`, `orig_bytes`, `resp_bytes`.
- Traffic patterns are made intentionally low-volume but periodic, mimicking heartbeat messages.
- Uses an IP pool to randomly assign source and destination hosts.
- Repeats log injection at fixed intervals (e.g., every 60 seconds) for realism.
- All logs are JSON-encoded and placed in to the Wazuh index.

---

### **6.4 Suspicious Login Simulation**

This script mimics anomalous login behavior in a Keycloak-backed environment.

**Implementation Highlights**:

- Brute forces Keycloak instance with a user, with fields like `User ID`, `Country`, and `event_hour`.
- Designed to simulate:
    - Logins from unexpected countries,
    - Frequent logins in a short time window.
- Keycloak logs are retrieved to be sentinto Wazuh index.

## **7. Evaluate Phase**

The **Evaluate Phase** is the final and most critical stage of the RADAR Test Framework. Its primary goal is to assess the effectiveness of anomaly detection by comparing the outputs of the detection pipeline (from OpenSearch) with the ground-truth labels defined in scenario datasets.

This phase systematically computes standard classification metrics, **True Positives (TP)**, **False Positives (FP)**, **True Negatives (TN)**, and **False Negatives (FN),** and generates structured CSV reports summarizing detection accuracy.

Each scenario has a dedicated evaluator script implemented as a class-based Python module. These scripts query the detection result index created during the setup phase and align results with labeled events to quantify detection performance.

---

### **7.1 Evaluation Workflow**

Each evaluator follows this general workflow:

1. **Load Ground Truth Labels**:
    
    Load the scenario’s CSV file containing timestamps and labels (e.g., `label_csv_path` in `config.yaml`). Labels typically indicate whether an event was malicious (`1`) or benign (`0`).
    
2. **Query Anomaly Detection Results**:
    
    Connect to OpenSearch and fetch all anomaly results from the detector’s `result_index` (e.g., `opensearch-ad-plugin-result-insider_threat`).
    
3. **Match Events with Anomalies**:
    
    For each labeled event identify corresponding anomaly detection result (same user/IP and closest timestamp).
    
4. **Assign Detection Outcome**:
    
    Based on the label and detection result:
    
    - **TP**: Label = 1, detected = Yes
    - **FP**: Label = 0, detected = Yes
    - **FN**: Label = 1, detected = No
    - **TN**: Label = 0, detected = No
5. **Write Evaluation Report:** Save a CSV file containing the per-event record.

This output allows downstream computation of:

- **Precision = TP / (TP + FP)**
- **Recall = TP / (TP + FN)**
- **F1 Score**
- **False positive rate**

---

### **7.2 Output Structure and Post-Processing**

Each evaluator writes its results to the `evaluation_results/` directory in CSV format. These outputs can be consumed by:

- External scripts for metric aggregation
- Dashboards for visual inspection
- Machine learning models for supervised re-training

## **9. Deployment & Usage Guide**

This section provides practical instructions for setting up, configuring, and executing the RADAR Test Framework in both containerized and hybrid environments. The framework is built for flexibility and reproducibility, allowing users to deploy it locally for experimentation or adapt it to enterprise environments for real-world security evaluations.

---

### **9.1 Prerequisites**

Before deploying the framework, ensure the following components are installed:

- **Docker** (≥ 20.10) and **Docker Compose**
- **Python 3.8+** with `pip`
- **Ansible** (for configuration provisioning)
- Sufficient resources (RAM, CPU) to run multiple containers
- Optional: Keycloak knowledge base if using `suspicious_login`

---

### **9.2 Environment Setup**

### Step 1: Install Dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Step 2: Start the Containerized Environment

```bash
docker compose up -d
```

This brings up the full environment:

- `wazuh.manager`
- `wazuh.agent` (with logs injected via simulator)
- `wazuh.indexer` (OpenSearch backend)
- `wazuh.dashboard` (UI)
- `keycloak`
- `webhook-server`

Wait until all containers are healthy and accessible.

---

### **9.3 Configuration**

### Step 1. Edit the `config.yaml` file to:

- Set `index_prefix`, thresholds, and log paths
- Define feature aggregations

### Step 2. Rename `env_var.env` to `.env`.

You may also edit `ansible/hosts` to match your infrastructure (e.g., if using IPs or SSH access to bare-metal Wazuh instances).

---

### **9.4 Running the Full Pipeline**

To run all four phases (ingest, setup, simulate, evaluate):

```bash
python mainctl.py --scenario insider_threat --phase all
```

To execute only selected phases:

```bash
python mainctl.py --scenario ddos_detection --phase setup
```

Supported arguments include:

- `-scenario <name>`
- `-phase <phase>`

---

### **9.5 Stopping the Environment**

To shut down and remove all containers:

```bash
docker compose down
```

## **10. Limitations & Future Work**

While the RADAR Test Framework provides a modular and reproducible environment for evaluating anomaly detection systems, it has inherent limitations that arise from its architectural assumptions, scope of simulation, and reliance on synthetic data. This section outlines key limitations and proposes directions for future research and system improvements.

---

### **10.1 Limitations**

### **1. Synthetic Data vs. Real-World Complexity**

Although the simulation modules attempt to mimic realistic attack behavior, they inevitably simplify system interactions:

- File access logs, network flows, and login events are **artificially generated** rather than captured from real endpoints.
- Behavioral patterns (e.g., insider misuse) may not reflect the subtlety of genuine user deviations over time.

This could result in:

- **Overfitting** of detection to clear anomalies.
- Reduced generalizability when applied to production logs with noise, edge cases, or unknown behaviors.

### **2. Limited Scenario Coverage**

The framework currently supports four scenarios:

- Insider Threat
- DDoS Attack
- Malware Communication
- Suspicious Login

While these represent common threat vectors, the framework does not yet include:

- Credential stuffing
- Data exfiltration via covert channels
- Advanced persistent threats (APTs)
- Insider privilege escalation

Adding more diverse and chained attack simulations would improve coverage.

### **3. Fixed Feature Space**

Each scenario defines a static list of features in `config.yaml`. While these features are sufficient for basic detection:

- They do not adapt dynamically to evolving datasets.
- Feature engineering is manual and limited to OpenSearch-supported aggregations.
- No support exists for contextual features or graph-based profiling (e.g., lateral movement detection).

### **4. Evaluation Simplification**

The evaluation pipeline assumes:

- Ground truth is available and correctly labeled in CSV format.
- Matching is done via timestamp and one categorical field (e.g., user, IP).
- Detection is binary based on anomaly grade and confidence.

This makes it difficult to:

- Handle multi-label events or overlapping anomalies.
- Evaluate detection quality under uncertain or partially labeled conditions.
- Analyze time-to-detection or latency-based metrics.

### **5. Dependency on Specific Stack**

The framework is tightly coupled with:

- Wazuh + OpenSearch for detection
- Docker for orchestration
- Ansible for configuration
- Keycloak for login simulation

Adapting the framework to other SIEMs, cloud-based platforms (e.g., Elastic Cloud), or alternate identity providers would require significant reconfiguration.

---

### **10.2 Future Work**

To address the limitations above and enhance the research utility of the framework, we propose the following extensions:

### **1. Integration of Real Logs**

- Incorporate logs from real systems (e.g., production endpoints, honeypots, or open-source datasets).
- Validate detection performance under realistic noise and normal behavior baselines.

### **2. Expand Scenario Library**

- Add complex, multi-stage attack simulations (e.g., phishing → credential use → exfiltration).
- Integrate MITRE ATT&CK mapping for coverage validation.
- Include cloud-native threats (IAM abuse, misconfigurations).

### **3. Dynamic Feature Selection**

- Enable automatic feature extraction and ranking from indexed logs.
- Support richer aggregations (e.g., time-series deltas, rolling statistics).
- Explore hybrid approaches combining OpenSearch and external ML engines (e.g., scikit-learn, PyOD).

### **4. Enhanced Evaluation Framework**

- Support probabilistic labels and soft detections.
- Measure performance over time (early vs late detection).
- Compute cost-sensitive metrics (e.g., detection cost vs response cost).

### **5. Platform Agnosticism**

- Abstract the detection backend to support other systems (e.g., Splunk, Graylog).
- Modularize simulation and evaluation logic to support heterogeneous environments (on-prem, cloud, hybrid).