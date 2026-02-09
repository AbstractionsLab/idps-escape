#!/usr/bin/env python3
"""
Generate realistic Wazuh test data for Linux resource monitoring.

This script creates two JSON files:
1. resource_monitoring_training.json - Normal resource usage patterns for baseline training
2. resource_monitoring_detection.json - Data with resource anomalies for detection testing

Usage:
    python generate_resource_data.py [--output-dir ./resource_monitoring]

The generated data simulates realistic system resource patterns with:
- Normal CPU and memory usage fluctuations
- Business-hours load patterns
- Periodic batch jobs
- Injected anomalies (CPU spikes, memory leaks, resource exhaustion)
"""

import argparse
import json
import math
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
    {"id": "007", "name": "backup-server-01", "ip": "192.168.1.50"},
    {"id": "008", "name": "monitoring-server-01", "ip": "192.168.1.60"},
]

# Rule definitions for resource monitoring alerts
RULES = {
    "resource_check": {
        "id": 8001,
        "level": 3,
        "description": "System resource monitoring check",
        "groups": ["system_monitor", "performance", "syslog"],
    },
    "high_cpu": {
        "id": 8010,
        "level": 7,
        "description": "High CPU usage detected",
        "groups": ["system_monitor", "performance", "high_cpu"],
    },
    "high_memory": {
        "id": 8020,
        "level": 7,
        "description": "High memory usage detected",
        "groups": ["system_monitor", "performance", "high_memory"],
    },
    "resource_exhaustion": {
        "id": 8050,
        "level": 12,
        "description": "Potential resource exhaustion attack",
        "groups": ["system_monitor", "performance", "attack", "resource_exhaustion"],
    },
}


def generate_timestamp(base: datetime, offset_minutes: float) -> str:
    """Generate ISO 8601 timestamp."""
    ts = base + timedelta(minutes=offset_minutes)
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def calculate_baseline_usage(
    hour: int, 
    minute: int, 
    server_type: str,
    base_cpu: float = 25.0,
    base_memory: float = 40.0
) -> tuple[float, float]:
    """
    Calculate baseline CPU and memory usage based on time and server type.
    
    Returns (cpu_usage, memory_usage) as percentages.
    """
    # Time-based patterns
    time_factor = 1.0
    if 9 <= hour <= 17:  # Business hours
        time_factor = 1.3
    elif 0 <= hour <= 6:  # Night hours
        time_factor = 0.7
    
    # Server-specific patterns
    if "web-server" in server_type:
        base_cpu *= 1.2  # Web servers typically higher CPU
        base_memory *= 0.9
    elif "db-server" in server_type:
        base_cpu *= 0.9
        base_memory *= 1.4  # Databases use more memory
    elif "backup-server" in server_type:
        # Periodic spikes during backup windows (2-4 AM)
        if 2 <= hour <= 4:
            base_cpu *= 2.0
            base_memory *= 1.3
    elif "app-server" in server_type:
        base_cpu *= 1.1
        base_memory *= 1.1
    
    # Add periodic variations (sine wave for smooth transitions)
    period_minutes = hour * 60 + minute
    cpu_variation = 5 * math.sin(2 * math.pi * period_minutes / 180)  # 3-hour cycle
    memory_variation = 3 * math.sin(2 * math.pi * period_minutes / 240)  # 4-hour cycle
    
    # Calculate final values with time factor
    cpu = base_cpu * time_factor + cpu_variation + random.uniform(-3, 3)
    memory = base_memory * time_factor + memory_variation + random.uniform(-2, 2)
    
    # Clamp to valid ranges
    cpu = max(1.0, min(98.0, cpu))
    memory = max(10.0, min(95.0, memory))
    
    return round(cpu, 2), round(memory, 2)


def create_resource_alert(
    timestamp: str,
    rule_key: str,
    agent: Dict[str, str],
    cpu_usage: float,
    memory_usage: float,
) -> Dict[str, Any]:
    """Create a Wazuh resource monitoring alert document."""
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
        "data": {
            "cpu_usage_%": cpu_usage,
            "memory_usage_%": memory_usage,
            "title": "resource monitoring",
        },
        "decoder": {"name": "sysmon"},
        "location": "/var/log/sysstat",
        "full_log": f"CPU: {cpu_usage}%, Memory: {memory_usage}% on {agent['name']}",
    }
    
    return alert


def generate_normal_resource_data(
    start: datetime, 
    hours: int, 
    samples_per_hour: int = 60
) -> List[Dict[str, Any]]:
    """
    Generate normal system resource monitoring data.
    
    Creates realistic patterns:
    - Regular monitoring intervals (1 sample per minute)
    - Time-of-day variations
    - Server-type specific patterns
    - Small random fluctuations
    """
    alerts = []
    
    for hour in range(hours):
        for sample in range(samples_per_hour):
            minute = sample
            offset_minutes = hour * 60 + minute
            
            current_time = start + timedelta(minutes=offset_minutes)
            ts = generate_timestamp(start, offset_minutes)
            
            # Each agent reports independently
            for agent in AGENTS:
                cpu, memory = calculate_baseline_usage(
                    current_time.hour,
                    minute,
                    agent["name"]
                )
                
                # Determine rule based on usage levels
                if cpu > 85 or memory > 90:
                    rule_key = "resource_exhaustion"
                elif cpu > 70:
                    rule_key = "high_cpu"
                elif memory > 80:
                    rule_key = "high_memory"
                else:
                    rule_key = "resource_check"
                
                alerts.append(create_resource_alert(ts, rule_key, agent, cpu, memory))
    
    return alerts


def inject_cpu_spike_attack(
    alerts: List[Dict[str, Any]],
    start: datetime,
    attack_start_hour: int,
    duration_minutes: int = 45,
    affected_agents: List[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    """
    Inject a sustained CPU spike (crypto mining simulation).
    
    Simulates:
    - Sudden CPU usage increase to 90-98%
    - Sustained high usage over duration
    - Multiple hosts potentially affected (botnet-style)
    """
    if affected_agents is None:
        # Pick 2-3 random servers
        affected_agents = random.sample(AGENTS, k=random.randint(2, 3))
    
    attack_start = start + timedelta(hours=attack_start_hour)
    
    for minute in range(duration_minutes):
        offset = minute
        ts = generate_timestamp(attack_start, offset)
        
        for agent in affected_agents:
            # Anomalous CPU: 88-98%, with some variation
            cpu = random.uniform(88, 98)
            
            # Memory increases slightly but not as dramatically
            normal_cpu, normal_memory = calculate_baseline_usage(
                attack_start.hour, minute, agent["name"]
            )
            memory = min(95, normal_memory + random.uniform(10, 20))
            
            rule_key = "resource_exhaustion"
            alerts.append(create_resource_alert(ts, rule_key, agent, cpu, memory))
    
    return alerts


def inject_memory_leak(
    alerts: List[Dict[str, Any]],
    start: datetime,
    attack_start_hour: int,
    duration_minutes: int = 60,
    target_agent: Dict[str, str] = None,
) -> List[Dict[str, Any]]:
    """
    Inject a gradual memory leak pattern.
    
    Simulates:
    - Slowly increasing memory usage
    - Eventually reaching critical levels
    - CPU remains relatively normal
    """
    if target_agent is None:
        target_agent = random.choice(AGENTS)
    
    attack_start = start + timedelta(hours=attack_start_hour)
    
    # Start from a moderate level and increase
    start_memory = 50.0
    end_memory = 95.0
    
    for minute in range(duration_minutes):
        offset = minute
        ts = generate_timestamp(attack_start, offset)
        
        # Linear increase with some noise
        progress = minute / duration_minutes
        memory = start_memory + (end_memory - start_memory) * progress
        memory += random.uniform(-2, 2)
        memory = min(98, max(start_memory, memory))
        
        # CPU relatively normal
        cpu, _ = calculate_baseline_usage(attack_start.hour, minute, target_agent["name"])
        cpu += random.uniform(-5, 10)  # Slight increase due to paging
        
        rule_key = "high_memory" if memory > 80 else "resource_check"
        if memory > 90:
            rule_key = "resource_exhaustion"
        
        alerts.append(create_resource_alert(ts, rule_key, target_agent, cpu, memory))
    
    return alerts


def inject_fork_bomb(
    alerts: List[Dict[str, Any]],
    start: datetime,
    attack_start_hour: int,
    duration_minutes: int = 10,
    target_agent: Dict[str, str] = None,
) -> List[Dict[str, Any]]:
    """
    Inject a fork bomb pattern (rapid resource exhaustion).
    
    Simulates:
    - Sudden spike in both CPU and memory
    - Very high usage levels
    - Short duration (system typically crashes or auto-kills processes)
    """
    if target_agent is None:
        target_agent = random.choice(AGENTS)
    
    attack_start = start + timedelta(hours=attack_start_hour)
    
    for minute in range(duration_minutes):
        offset = minute
        ts = generate_timestamp(attack_start, offset)
        
        # Both CPU and memory spike dramatically
        cpu = random.uniform(92, 99)
        memory = random.uniform(88, 98)
        
        rule_key = "resource_exhaustion"
        alerts.append(create_resource_alert(ts, rule_key, target_agent, cpu, memory))
    
    return alerts


def main():
    """Generate resource monitoring test data."""
    parser = argparse.ArgumentParser(
        description="Generate Wazuh test data for Linux resource monitoring"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="./resource_monitoring",
        help="Output directory for generated JSON files",
    )
    parser.add_argument(
        "--training-hours",
        type=int,
        default=168,
        help="Hours of normal data for training (default: 168 = 7 days)",
    )
    parser.add_argument(
        "--detection-hours",
        type=int,
        default=6,
        help="Hours of data for detection testing (default: 6)",
    )
    
    args = parser.parse_args()
    
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Generating resource monitoring test data...")
    print(f"Output directory: {output_dir}")
    
    # Generate training data (normal patterns only)
    print(f"\n1. Generating {args.training_hours} hours of normal training data...")
    training_start = datetime(2024, 12, 1, 0, 0, 0)
    training_data = generate_normal_resource_data(
        training_start, 
        args.training_hours,
        samples_per_hour=60  # 1 per minute
    )
    
    print(f"   Generated {len(training_data)} training alerts")
    
    # Sort by timestamp
    training_data.sort(key=lambda x: x["timestamp"])
    
    # Save training data
    training_file = output_dir / "resource_monitoring_training.json"
    with open(training_file, "w") as f:
        json.dump(training_data, f, indent=2)
    print(f"   Saved to: {training_file}")
    
    # Generate detection data (with anomalies)
    print(f"\n2. Generating {args.detection_hours} hours of detection data with anomalies...")
    detection_start = datetime(2024, 12, 15, 0, 0, 0)
    detection_data = generate_normal_resource_data(
        detection_start,
        args.detection_hours,
        samples_per_hour=60
    )
    
    print(f"   Generated {len(detection_data)} base detection alerts")
    
    # Inject various attack patterns
    print("   Injecting attack patterns:")
    
    # Attack 1: CPU spike (crypto mining) at hour 1
    print("     - CPU spike attack (crypto mining) at hour 1")
    detection_data = inject_cpu_spike_attack(
        detection_data,
        detection_start,
        attack_start_hour=1,
        duration_minutes=45
    )
    
    # Attack 2: Memory leak at hour 3
    print("     - Memory leak pattern at hour 3")
    detection_data = inject_memory_leak(
        detection_data,
        detection_start,
        attack_start_hour=3,
        duration_minutes=60
    )
    
    # Attack 3: Fork bomb at hour 5
    print("     - Fork bomb attack at hour 5")
    detection_data = inject_fork_bomb(
        detection_data,
        detection_start,
        attack_start_hour=5,
        duration_minutes=8
    )
    
    print(f"   Total detection alerts: {len(detection_data)}")
    
    # Sort by timestamp
    detection_data.sort(key=lambda x: x["timestamp"])
    
    # Save detection data
    detection_file = output_dir / "resource_monitoring_detection.json"
    with open(detection_file, "w") as f:
        json.dump(detection_data, f, indent=2)
    print(f"   Saved to: {detection_file}")
    
    # Print summary statistics
    print("\n" + "=" * 60)
    print("GENERATION COMPLETE")
    print("=" * 60)
    print(f"\nTraining data:")
    print(f"  File: {training_file}")
    print(f"  Alerts: {len(training_data)}")
    print(f"  Time range: {training_data[0]['timestamp']} to {training_data[-1]['timestamp']}")
    
    print(f"\nDetection data:")
    print(f"  File: {detection_file}")
    print(f"  Alerts: {len(detection_data)}")
    print(f"  Time range: {detection_data[0]['timestamp']} to {detection_data[-1]['timestamp']}")
    print(f"\nAttack patterns included:")
    print(f"  1. CPU spike (hour 1, 45 minutes)")
    print(f"  2. Memory leak (hour 3, 60 minutes)")
    print(f"  3. Fork bomb (hour 5, 8 minutes)")
    
    print("\n" + "=" * 60)
    print("Usage:")
    print(f"  poetry run sonar train --scenario scenarios/linux_resource_monitoring.yaml --debug")
    print(f"  poetry run sonar detect --scenario scenarios/linux_resource_monitoring.yaml --debug")
    print("=" * 60)


if __name__ == "__main__":
    main()
