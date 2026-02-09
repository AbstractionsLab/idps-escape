#!/usr/bin/env python3
"""
Generate realistic Wazuh test data with various attack patterns.

This script creates two JSON files:
1. normal_training.json - Normal authentication patterns for baseline training
2. attack_scenarios.json - Data containing various attack patterns for detection testing

Usage:
    python generate_attack_data.py [--output-dir ./generated_scenarios]

The generated data simulates realistic enterprise authentication patterns with:
- Normal business-hours activity
- Periodic system events
- Injected attack sequences (brute force, lateral movement, privilege escalation)
"""

import argparse
import json
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List

# Seed for reproducibility
random.seed(42)

# Configuration
AGENTS = [
    {"id": "001", "name": "web-server-01", "ip": "192.168.1.10"},
    {"id": "002", "name": "web-server-02", "ip": "192.168.1.11"},
    {"id": "003", "name": "db-server-01", "ip": "192.168.1.20"},
    {"id": "004", "name": "app-server-01", "ip": "192.168.1.30"},
    {"id": "005", "name": "app-server-02", "ip": "192.168.1.31"},
    {"id": "006", "name": "file-server-01", "ip": "192.168.1.40"},
    {"id": "007", "name": "dev-workstation-01", "ip": "192.168.2.10"},
    {"id": "008", "name": "dev-workstation-02", "ip": "192.168.2.11"},
    {"id": "009", "name": "admin-workstation-01", "ip": "192.168.3.10"},
    {"id": "010", "name": "jump-server-01", "ip": "192.168.1.100"},
]

NORMAL_SRCIPS = [
    "192.168.1.100", "192.168.1.101", "192.168.1.102",
    "192.168.2.50", "192.168.2.51", "192.168.2.52",
    "10.0.0.10", "10.0.0.11",
]

MALICIOUS_SRCIPS = [
    "203.0.113.100",  # External attacker
    "203.0.113.101",
    "198.51.100.50",  # Known bad IP
    "45.33.32.156",   # Scanner
]

USERS = ["admin", "root", "operator", "sysadmin", "devuser", "appuser", "backup"]
ATTACK_USERS = ["admin", "root", "administrator", "test", "guest"]

# Rule definitions matching real Wazuh rules
RULES = {
    # Normal authentication
    "ssh_success": {
        "id": 5715,
        "level": 3,
        "description": "sshd: authentication success.",
        "groups": ["authentication_success", "sshd", "ssh"],
    },
    "ssh_failed": {
        "id": 5710,
        "level": 5,
        "description": "sshd: Attempt to login using a non-existent user",
        "groups": ["authentication_failed", "sshd", "ssh"],
    },
    "ssh_invalid_user": {
        "id": 5711,
        "level": 5,
        "description": "sshd: Attempt to login using a denied user.",
        "groups": ["authentication_failed", "sshd", "ssh", "invalid_login"],
    },
    "brute_force": {
        "id": 5712,
        "level": 10,
        "description": "sshd: brute force trying to get access to the system.",
        "groups": ["authentication_failed", "sshd", "ssh", "brute_force"],
    },
    "sudo_success": {
        "id": 5402,
        "level": 3,
        "description": "Successful sudo to ROOT executed.",
        "groups": ["pam", "syslog", "sudo"],
    },
    "sudo_failed": {
        "id": 5401,
        "level": 5,
        "description": "Failed attempt to run sudo.",
        "groups": ["pam", "syslog", "sudo", "authentication_failed"],
    },
    "user_added": {
        "id": 5901,
        "level": 8,
        "description": "New user added to the system.",
        "groups": ["syslog", "account_changed", "user_management"],
    },
    "password_changed": {
        "id": 5902,
        "level": 8,
        "description": "User password changed.",
        "groups": ["syslog", "account_changed"],
    },
    "privilege_escalation": {
        "id": 5403,
        "level": 14,
        "description": "Possible privilege escalation attempt.",
        "groups": ["pam", "privilege_escalation", "attack"],
    },
    "session_opened": {
        "id": 5501,
        "level": 3,
        "description": "PAM: Login session opened.",
        "groups": ["pam", "syslog", "session_opened", "authentication_success"],
    },
    "multiple_auth_failures": {
        "id": 5720,
        "level": 10,
        "description": "Multiple authentication failures.",
        "groups": ["authentication_failed", "brute_force"],
    },
}


def generate_timestamp(base: datetime, offset_minutes: float) -> str:
    """Generate ISO 8601 timestamp."""
    ts = base + timedelta(minutes=offset_minutes)
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def create_alert(
    timestamp: str,
    rule_key: str,
    agent: Dict[str, str],
    srcip: str,
    user: str = "unknown",
    extra: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """Create a Wazuh alert document."""
    rule = RULES[rule_key]
    alert = {
        "timestamp": timestamp,
        "rule": {
            "id": rule["id"],
            "level": rule["level"],
            "description": rule["description"],
            "groups": rule["groups"].copy(),
        },
        "agent": agent.copy(),
        "manager": {"name": "wazuh-manager"},
        "srcip": srcip,
        "data": {"srcuser": user},
        "decoder": {"name": "sshd" if "ssh" in rule["groups"] else "pam"},
        "location": "/var/log/auth.log",
        "full_log": f"{rule['description']} - user: {user} from {srcip}",
    }
    if extra:
        alert.update(extra)
    return alert


def generate_normal_traffic(
    start: datetime, hours: int, alerts_per_hour: int = 50
) -> List[Dict[str, Any]]:
    """
    Generate normal authentication traffic patterns.
    
    Simulates typical enterprise patterns:
    - Higher activity during business hours (9-17)
    - Lower activity at night
    - Mostly successful logins with occasional failures
    - Regular sudo usage
    """
    alerts = []
    
    for hour in range(hours):
        current_hour = (start + timedelta(hours=hour)).hour
        
        # Activity multiplier based on time of day
        if 9 <= current_hour <= 17:
            multiplier = 1.5  # Business hours
        elif 6 <= current_hour <= 9 or 17 <= current_hour <= 20:
            multiplier = 1.0  # Transition hours
        else:
            multiplier = 0.3  # Night hours
        
        num_alerts = int(alerts_per_hour * multiplier * random.uniform(0.8, 1.2))
        
        for _ in range(num_alerts):
            offset = hour * 60 + random.uniform(0, 60)
            ts = generate_timestamp(start, offset)
            agent = random.choice(AGENTS)
            srcip = random.choice(NORMAL_SRCIPS)
            user = random.choice(USERS)
            
            # 85% success, 10% regular failure, 5% sudo
            r = random.random()
            if r < 0.85:
                rule_key = "ssh_success"
            elif r < 0.92:
                rule_key = "session_opened"
            elif r < 0.95:
                rule_key = "ssh_failed"
            else:
                rule_key = random.choice(["sudo_success", "sudo_failed"])
            
            alerts.append(create_alert(ts, rule_key, agent, srcip, user))
    
    return alerts


def inject_brute_force_attack(
    alerts: List[Dict[str, Any]],
    start: datetime,
    attack_start_hour: int,
    duration_minutes: int = 30,
    attempts: int = 200,
) -> List[Dict[str, Any]]:
    """
    Inject a brute force attack sequence.
    
    Simulates an attacker trying many passwords on a single target.
    """
    attack_start = start + timedelta(hours=attack_start_hour)
    target_agent = random.choice(AGENTS[:3])  # Target a server
    attacker_ip = random.choice(MALICIOUS_SRCIPS)
    
    for i in range(attempts):
        offset = random.uniform(0, duration_minutes)
        ts = generate_timestamp(attack_start, offset)
        user = random.choice(ATTACK_USERS)
        
        # Mostly failures, occasional brute_force rule triggers
        if i < attempts - 5:
            if random.random() < 0.1:
                rule_key = "brute_force"
            else:
                rule_key = random.choice(["ssh_failed", "ssh_invalid_user"])
        else:
            # Last few attempts might succeed (compromised)
            rule_key = "ssh_success" if random.random() < 0.3 else "ssh_failed"
        
        alerts.append(create_alert(ts, rule_key, target_agent, attacker_ip, user))
    
    return alerts


def inject_lateral_movement(
    alerts: List[Dict[str, Any]],
    start: datetime,
    attack_start_hour: int,
    duration_minutes: int = 60,
) -> List[Dict[str, Any]]:
    """
    Inject lateral movement pattern.
    
    Simulates an attacker moving through multiple systems after initial compromise.
    """
    attack_start = start + timedelta(hours=attack_start_hour)
    attacker_ip = AGENTS[0]["ip"]  # Compromised first host
    
    # Move through multiple agents in sequence
    for i, agent in enumerate(AGENTS[1:6]):
        offset = i * 10 + random.uniform(0, 5)  # ~10 min between each hop
        
        # Few failures then success on each host
        for j in range(random.randint(1, 3)):
            ts = generate_timestamp(attack_start, offset + j * 0.5)
            alerts.append(create_alert(ts, "ssh_failed", agent, attacker_ip, "root"))
        
        ts = generate_timestamp(attack_start, offset + 3)
        alerts.append(create_alert(ts, "ssh_success", agent, attacker_ip, "root"))
        
        # Sudo attempt after login
        ts = generate_timestamp(attack_start, offset + 4)
        alerts.append(create_alert(ts, "sudo_success", agent, attacker_ip, "root"))
    
    return alerts


def inject_privilege_escalation(
    alerts: List[Dict[str, Any]],
    start: datetime,
    attack_start_hour: int,
) -> List[Dict[str, Any]]:
    """
    Inject privilege escalation attempt.
    
    Simulates an attacker trying to gain elevated privileges.
    """
    attack_start = start + timedelta(hours=attack_start_hour)
    target_agent = random.choice(AGENTS[6:9])  # Target a workstation
    attacker_ip = random.choice(NORMAL_SRCIPS)  # Insider or compromised internal
    
    events = [
        ("sudo_failed", 0),
        ("sudo_failed", 1),
        ("sudo_failed", 2),
        ("privilege_escalation", 5),
        ("user_added", 7),
        ("password_changed", 8),
        ("sudo_success", 10),
    ]
    
    for rule_key, offset in events:
        ts = generate_timestamp(attack_start, offset)
        alerts.append(create_alert(ts, rule_key, target_agent, attacker_ip, "attacker"))
    
    return alerts


def inject_password_spray(
    alerts: List[Dict[str, Any]],
    start: datetime,
    attack_start_hour: int,
    duration_minutes: int = 120,
) -> List[Dict[str, Any]]:
    """
    Inject password spraying attack.
    
    Simulates trying one or few passwords against many accounts to avoid lockout.
    """
    attack_start = start + timedelta(hours=attack_start_hour)
    attacker_ip = random.choice(MALICIOUS_SRCIPS)
    
    # Try same password against all users on all agents
    for i, agent in enumerate(AGENTS):
        for j, user in enumerate(USERS):
            offset = (i * len(USERS) + j) * (duration_minutes / (len(AGENTS) * len(USERS)))
            ts = generate_timestamp(attack_start, offset)
            
            # Mostly failures
            rule_key = "ssh_success" if random.random() < 0.02 else "ssh_failed"
            alerts.append(create_alert(ts, rule_key, agent, attacker_ip, user))
    
    return alerts


def main():
    parser = argparse.ArgumentParser(description="Generate Wazuh test data with attack patterns")
    parser.add_argument("--output-dir", type=Path, default=Path("./generated_scenarios"))
    args = parser.parse_args()
    
    args.output_dir.mkdir(parents=True, exist_ok=True)
    
    # Training data: 14 days of normal traffic
    print("Generating normal training data (14 days)...")
    training_start = datetime(2024, 12, 1, 0, 0, 0)
    training_alerts = generate_normal_traffic(training_start, hours=14*24, alerts_per_hour=40)
    
    training_file = args.output_dir / "normal_training.json"
    with open(training_file, "w") as f:
        json.dump(training_alerts, f, indent=2)
    print(f"  Created {training_file} with {len(training_alerts)} alerts")
    
    # Attack scenario data: 2 days with injected attacks
    print("Generating attack scenario data (2 days)...")
    attack_start = datetime(2024, 12, 20, 0, 0, 0)
    attack_alerts = generate_normal_traffic(attack_start, hours=48, alerts_per_hour=40)
    
    # Inject various attack patterns
    print("  Injecting brute force attack at hour 8...")
    attack_alerts = inject_brute_force_attack(attack_alerts, attack_start, 8)
    
    print("  Injecting lateral movement at hour 14...")
    attack_alerts = inject_lateral_movement(attack_alerts, attack_start, 14)
    
    print("  Injecting privilege escalation at hour 26...")
    attack_alerts = inject_privilege_escalation(attack_alerts, attack_start, 26)
    
    print("  Injecting password spray at hour 38...")
    attack_alerts = inject_password_spray(attack_alerts, attack_start, 38)
    
    # Sort by timestamp
    attack_alerts.sort(key=lambda x: x["timestamp"])
    
    attack_file = args.output_dir / "attack_scenarios.json"
    with open(attack_file, "w") as f:
        json.dump(attack_alerts, f, indent=2)
    print(f"  Created {attack_file} with {len(attack_alerts)} alerts")
    
    print("\nDone! Generated test data files:")
    print(f"  - {training_file}: Normal baseline for training")
    print(f"  - {attack_file}: Scenarios with attack patterns for detection testing")
    print("\nUsage:")
    print("  poetry run sonar train --scenario scenarios/brute_force_detection.yaml --debug")
    print("  poetry run sonar detect --scenario scenarios/brute_force_detection.yaml --debug")


if __name__ == "__main__":
    main()
