import argparse
import subprocess
import sys
from setup.config_loader import load_config
from setup.opensearch_config import OpenSearchConfig
from setup.detector import DetectorManager
from setup.monitor import MonitorManager
from setup.keycloak import KeycloakManager
from setup.webhook import WebhookManager
from simulate.insider_threat_simulator import InsiderThreatSimulator
from simulate.suspicious_login_simulator import SuspiciousLoginSimulator
from simulate.ddos_simulator import DDoSSimulator
from simulate.malcom_simulator import MalwareC2Simulator
from evaluate.insider_threat_evaluator import InsiderThreatEvaluator
from evaluate.susplog_evaluator import SuspiciousLoginEvaluator
from evaluate.ddos_evaluator import DDoSEvaluator
from evaluate.malcom_evaluator import MalwareC2Evaluator

def run_ansible_playbook(scenario_name):
    print(f"[→] Running Ansible for scenario: {scenario_name}")
    result = subprocess.run([
        "ansible-playbook",
        "-i", "ansible/hosts",
        "ansible/site.yml",
        "-e", f"scenario_name={scenario_name}"
    ])
    if result.returncode != 0:
        print("[✗] Ansible playbook failed.")
        sys.exit(1)


def run_dataset_ingestion(scenario_path):
    print(f"[→] Running ingestion from: {scenario_path}/wazuh_ingest.py")
    try:
        result = subprocess.run(
            ["python3", f"{scenario_path}/wazuh_ingest.py"],
            check=True,
            capture_output=True,
            text=True
        )
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print("[✗] Ingestion script failed:")
        print(e.stderr)

def setup_scenario(scenario: str, config, os_config):
    print(f"[✓] Starting setup for scenario: {scenario}")
    scenario_cfg = config.scenario_config[scenario]

    run_ansible_playbook(scenario)

    detector = DetectorManager(os_config)
    detector_id = detector.create_detector(
        index_name=scenario_cfg["index_prefix"] + "-*",
        time_field="@timestamp",
        feature_attributes=scenario_cfg.get("features", []),
        categorical_field=scenario_cfg.get("categorical_field", ""),
        detector_interval=scenario_cfg.get("detector_interval", 5),
        detector_delay=scenario_cfg.get("delay_minutes", 1),
        result_index=scenario_cfg.get("result_index", ""),
        name=f"radar-{scenario}",
        description=f"Detector for {scenario}"
    )

    monitor = MonitorManager(
        scenario_config=scenario_cfg,
        detector_id=detector_id,
        config=os_config
    )
    monitor.create_monitor()
    detector.start_detector(detector_id)

def ingest_data(scenario: str, config):
    print(f"[✓] Starting data ingestion for scenario: {scenario}")

    run_dataset_ingestion(f"../{scenario}")

    if scenario == "suspicious_login":
        kc = KeycloakManager(config)
        kc.authenticate()
        kc.create_realm_if_not_exists()
        kc.create_users_from_dataset()

def run_simulation(scenario: str, config):
    print(f"[✓] Starting simulation for scenario: {scenario}")

    if scenario == "insider_threat":
        sim = InsiderThreatSimulator(user_id="BAL0044", pc_name="agent.insider", app_config=config)
        sim.simulate_and_ingest(normal_count=3, anomaly_count=2)
    elif scenario == "suspicious_login":
        from setup.keycloak import KeycloakManager
        kc = KeycloakManager(config)
        kc.authenticate()
        sim = SuspiciousLoginSimulator(app_config=config)
        sim.keycloak = kc
        sim.simulate_logins(num_logins=10000)
        sim.collect_and_send_logs()
    elif scenario == "ddos_detection":
        sim = DDoSSimulator(app_config=config)
        sim.run_simulation(num_packets=15000, capture_timeout=500)
    elif scenario == "malware_communication":
        sim = MalwareC2Simulator(app_config=config)
        sim.simulate_attack(count=9000)
    else:
        print(f"[!] Unknown scenario: {scenario}")

def run_evaluation(scenario: str, config):
    print(f"[✓] Starting evaluation for scenario: {scenario}")

    if scenario == "insider_threat":
        evaluator = InsiderThreatEvaluator(config)
    elif scenario == "suspicious_login":
        evaluator = SuspiciousLoginEvaluator(config)
    elif scenario == "ddos_detection":
        evaluator = DDoSEvaluator(config)
    elif scenario == "malware_communication":
        evaluator = MalwareC2Evaluator(config)
    else:
        print(f"[!] Unknown scenario: {scenario}")
        return

    evaluator.run()

def main():
    parser = argparse.ArgumentParser(description="RADAR Main Controller")
    parser.add_argument("--scenario", required=False, default=None, help="Scenario name (e.g., insider_threat, suspicious_login, ddos_detection, malware_communication)")
    parser.add_argument("--phase", required=False, default="all", choices=["setup", "ingest", "simulate", "evaluate", "all"], help="Phase to execute")

    args = parser.parse_args()
    config = load_config()
    scenario = args.scenario or config.default_scenario
    os_config = OpenSearchConfig(config)

    if args.phase in ["setup", "all"]:
        setup_scenario(scenario, config, os_config)

    if args.phase in ["ingest", "all"]:
        ingest_data(scenario, config)

    if args.phase in ["simulate", "all"]:
        run_simulation(scenario, config)

    if args.phase in ["evaluate", "all"]:
        run_evaluation(scenario, config)


if __name__ == "__main__":
    main()
