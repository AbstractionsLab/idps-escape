import ipaddress
import subprocess
import requests
import csv
import json
import netifaces
import threading
import time
from pathlib import Path
from datetime import datetime, timezone
from scapy.all import IP, TCP, send, sniff, Raw
from setup.config_loader import AppConfig

class DDoSSimulator:
    def __init__(self, app_config: AppConfig):
        self.opensearch_url = app_config.opensearch_url
        self.auth = (app_config.opensearch_user, app_config.opensearch_pass)
        self.verify_cert = app_config.opensearch_verify_ssl
        self.container_name = app_config.scenario_config["ddos_detection"]["container_name"]
        self.target_ip = self.get_container_ip(self.container_name)
        self.target_port = app_config.scenario_config["ddos_detection"]["container_port"]
        self.index_prefix = app_config.scenario_config["ddos_detection"]["index_prefix"]
        self.label_csv_path = Path(__file__).resolve().parents[2] / app_config.scenario_config["ddos_detection"][
            "label_csv_path"]

        print(f"[+] Target container IP resolved: {self.target_ip}")


    def get_container_ip(self, name):
        result = subprocess.check_output([
                "docker", "inspect", "-f",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                name
        ]).decode().strip()
        return result

    def generate_syn_flood(self, num_packets=100):
        for i in range(num_packets):
            packet = IP(dst=self.target_ip) / TCP(dport=self.target_port, flags="S")
            send(packet, verbose=0)
            time.sleep(0.005)  # 5ms delay to avoid flooding too fast
        print(f"[+] Sent {num_packets} SYN packets to {self.target_ip}:{self.target_port}")

    def _get_docker_interface(self):
        try:
            target_ip = ipaddress.IPv4Address(self.target_ip)

            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        ip = addr_info.get('addr')
                        netmask = addr_info.get('netmask')

                        if ip and netmask:
                            try:
                                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                                if target_ip in network:
                                    print(f"[✓] Found interface '{iface}' for IP {target_ip} in network {network}")
                                    return iface
                            except ValueError:
                                continue

            raise RuntimeError(f"No matching interface found for IP {target_ip}")
        except Exception as e:
            raise RuntimeError(f"Interface detection failed: {e}")

    def _flatten_fields(self, data):
        def flatten(v):
            if isinstance(v, dict):
                return str(v)
            return v
        return {k: flatten(v) for k, v in data.items()}

    def write_to_ground_truth(self, formatted_packets: dict):
        csv_path = self.label_csv_path
        with open(csv_path, "a", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=formatted_packets.keys(), extrasaction='ignore')
            writer.writerow(formatted_packets)


    def capture_traffic(self, timeout=10):
        print("[*] Capturing traffic...")
        iface = self._get_docker_interface()
        packets = sniff(filter=f"tcp and dst host {self.target_ip}", timeout=timeout, iface=iface)
        print(f"[+] Captured {len(packets)} packets")
        for idx, pkt in enumerate(packets):
            if IP in pkt and TCP in pkt:
                doc = self.format_packet(pkt, idx)
                flat_doc = self._flatten_fields(doc)
                print(flat_doc)
                self.write_to_ground_truth(flat_doc)
                timestamp = datetime.now(timezone.utc)
                flat_doc["@timestamp"] = timestamp.isoformat()
                flat_doc["event_hour"] = timestamp.hour
                self.send_to_opensearch(flat_doc)

    def run_simulation(self, num_packets=50, capture_timeout=50):
        print("[✓] Starting DDoS simulation")

        # Start capture in a separate thread
        sniffer_thread = threading.Thread(target=self.capture_traffic, kwargs={'timeout': capture_timeout})
        sniffer_thread.start()

        # Let sniffer start first
        time.sleep(1)

        # Send packets
        self.generate_syn_flood(num_packets)

        # Wait for sniffer to finish
        sniffer_thread.join()

    def format_packet(self, pkt, idx):
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        flags = pkt[TCP].flags
        length = len(pkt)

        return {
            "Unnamed:_0": idx,
            "Flow_ID": f"{ip_src}-{ip_dst}-{src_port}-{dst_port}-6",
            "Source_IP": ip_src,
            "Source_Port": src_port,
            "Destination_IP": ip_dst,
            "Destination_Port": dst_port,
            "Protocol": 6,
            "Timestamp": datetime.now(timezone.utc).isoformat(),
            "Flow_Duration": 1000000,
            "Total_Fwd_Packets": 1,
            "Total_Backward_Packets": 10,
            "Total_Length_of_Fwd_Packets": length,
            "Total_Length_of_Bwd_Packets": 0,
            "Fwd_Packet_Length_Max": length,
            "Fwd_Packet_Length_Min": length,
            "Fwd_Packet_Length_Mean": length,
            "Fwd_Packet_Length_Std": 0.0,
            "Bwd_Packet_Length_Max": 0,
            "Bwd_Packet_Length_Min": 0,
            "Bwd_Packet_Length_Mean": 0.0,
            "Bwd_Packet_Length_Std": 0.0,
            "Flow_Bytes_s": 60000.0,
            "Flow_Packets_s": 250000.0,
            "Flow_IAT_Mean": 0,
            "Flow_IAT_Std": 0,
            "Flow_IAT_Max": 0,
            "Flow_IAT_Min": 0,
            "Fwd_IAT_Total": 0,
            "Fwd_IAT_Mean": 0,
            "Fwd_IAT_Std": 0,
            "Fwd_IAT_Max": 0,
            "Fwd_IAT_Min": 0,
            "Bwd_IAT_Total": 0,
            "Bwd_IAT_Mean": 0,
            "Bwd_IAT_Std": 0,
            "Bwd_IAT_Max": 0,
            "Bwd_IAT_Min": 0,
            "Fwd_PSH_Flags": 0,
            "Bwd_PSH_Flags": 0,
            "Fwd_URG_Flags": 0,
            "Bwd_URG_Flags": 0,
            "Fwd_Header_Length": 40,
            "Bwd_Header_Length": 0,
            "Fwd_Packets_s": 1.0,
            "Bwd_Packets_s": 0.0,
            "Min_Packet_Length": length,
            "Max_Packet_Length": length,
            "Packet_Length_Mean": length,
            "Packet_Length_Std": 0.0,
            "Packet_Length_Variance": 0.0,
            "FIN_Flag_Count": int("F" in flags),
            "SYN_Flag_Count": int("S" in flags),
            "RST_Flag_Count": int("R" in flags),
            "PSH_Flag_Count": int("P" in flags),
            "ACK_Flag_Count": int("A" in flags),
            "URG_Flag_Count": int("U" in flags),
            "CWE_Flag_Count": 0,
            "ECE_Flag_Count": 0,
            "Down_Up_Ratio": 0.0,
            "Average_Packet_Size": length,
            "Avg_Fwd_Segment_Size": length,
            "Avg_Bwd_Segment_Size": 0,
            "Fwd_Header_Length_1": 40,
            "Fwd_Avg_Bytes_Bulk": 0,
            "Fwd_Avg_Packets_Bulk": 0,
            "Fwd_Avg_Bulk_Rate": 0,
            "Bwd_Avg_Bytes_Bulk": 0,
            "Bwd_Avg_Packets_Bulk": 0,
            "Bwd_Avg_Bulk_Rate": 0,
            "Subflow_Fwd_Packets": 1,
            "Subflow_Fwd_Bytes": length,
            "Subflow_Bwd_Packets": 0,
            "Subflow_Bwd_Bytes": 0,
            "Init_Win_bytes_forward": 5840,
            "Init_Win_bytes_backward": 0,
            "act_data_pkt_fwd": 1,
            "min_seg_size_forward": 20,
            "Active_Mean": 1.0,
            "Active_Std": 0.0,
            "Active_Max": 1.0,
            "Active_Min": 1.0,
            "Idle_Mean": 0.0,
            "Idle_Std": 0.0,
            "Idle_Max": 0.0,
            "Idle_Min": 0.0,
            "SimillarHTTP": 0,
            "Inbound": 1,
            "Label": "Syn"
        }

    def send_to_opensearch(self, log_entry):
        try:
            index_name = f"{self.index_prefix}-{log_entry['@timestamp'][:10]}"
            response = requests.post(
                    f"{self.opensearch_url}/{index_name}/_doc",
                    auth=self.auth,
                    headers={"Content-Type": "application/json"},
                    data=json.dumps(log_entry),
                    verify=self.verify_cert,
                    timeout=10
            )
            if response.status_code >= 300:
                print(f"[!] OpenSearch error: {response.status_code} - {response.text}")
            else:
                print(f"[+] Ingested: {log_entry['Flow_ID']}")
        except Exception as e:
            print(f"[!] Ingestion failed: {e}")
