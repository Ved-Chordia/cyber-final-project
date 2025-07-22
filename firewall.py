
import json
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import os

def load_rules():
    with open("rules.json", "r") as f:
        return json.load(f)

def match_rule(packet, rules):
    proto = None
    port = None

    if packet.haslayer(TCP):
        proto = "TCP"
        port = packet[TCP].dport
    elif packet.haslayer(UDP):
        proto = "UDP"
        port = packet[UDP].dport
    elif packet.haslayer(ICMP):
        proto = "ICMP"

    for rule in rules:
        if rule["protocol"] == proto:
            if proto == "ICMP" or rule.get("port") == port:
                return rule
    return None

def log_packet(packet, rule):
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    filename = os.path.join(log_dir, "firewall_log.txt")
    with open(filename, "a") as f:
        f.write(f"[{datetime.now()}] Dropped packet -> Protocol: {rule['protocol']}, Port: {rule.get('port')}, Src: {packet[IP].src}, Dst: {packet[IP].dst}\n")

def process_packet(packet):
    if IP in packet:
        rule = match_rule(packet, rules)
        if rule and rule["action"] == "block":
            print(f"[!] Dropped packet: {rule['protocol']} Port {rule.get('port')} from {packet[IP].src} to {packet[IP].dst}")
            log_packet(packet, rule)
        elif rule and rule["action"] == "allow":
            print(f"[+] Allowed packet: {rule['protocol']} Port {rule.get('port')} from {packet[IP].src} to {packet[IP].dst}")
        else:
            print(f"[.] No rule matched: Packet from {packet[IP].src} to {packet[IP].dst}")

rules = load_rules()

print("[*] Starting personal firewall...")
sniff(filter="ip", prn=process_packet, store=0)
