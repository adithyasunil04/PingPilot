import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
import torch
import numpy as np
from collections import deque
import time
import subprocess
import datetime
from os import name as OS_NAME
import sys

# Constants
SEQUENCE_LENGTH = 5
NUM_FEATURES = 12  # Increased to match enhanced feature set
CAPTURE_DURATION = None

# Gaming Traffic Port Definitions
GAMING_PORTS = {
    'TCP': {
        27015: 'Steam', 27016: 'Steam', 27017: 'Steam', 27018: 'Steam', 27019: 'Steam',
        27020: 'CSGO', 27021: 'CSGO', 8393: 'Valorant', 8394: 'Valorant',
        3074: 'Xbox Live', 24000: 'PUBG', 24001: 'PUBG', 24002: 'PUBG',
        27014: 'Call of Duty', 27015: 'Call of Duty',
        10000: 'R6 Siege', 10001: 'R6 Siege', 10002: 'R6 Siege',
        5222: 'Fortnite', 5795: 'Fortnite', 5847: 'Fortnite',
        25565: 'Minecraft', 25575: 'Minecraft', 2099: 'League of Legends',
        5000: 'League of Legends', 5223: 'League of Legends', 8393: 'League of Legends',
        8394: 'League of Legends', 8088: 'League of Legends'
    },
    'UDP': {
        27015: 'Steam', 27016: 'Steam', 27017: 'Steam', 27018: 'Steam', 27019: 'Steam',
        27020: 'CSGO', 27021: 'CSGO', 8401: 'Valorant', 3074: 'Xbox Live', 3075: 'PSN',
        24000: 'PUBG', 24001: 'PUBG', 24002: 'PUBG', 3075: 'Call of Duty',
        3076: 'Call of Duty', 3077: 'Call of Duty', 3078: 'Call of Duty',
        10000: 'R6 Siege', 10001: 'R6 Siege', 10002: 'R6 Siege', 5222: 'Fortnite',
        5795: 'Fortnite', 5847: 'Fortnite', 9000: 'Fortnite', 9001: 'Fortnite',
        19132: 'Minecraft Bedrock', 25565: 'Minecraft Java', 5000: 'League of Legends',
        5100: 'League of Legends', 8393: 'League of Legends', 8394: 'League of Legends',
        8088: 'League of Legends'
    }
}

def extract_features(packet):
    """Enhanced feature extraction with QoS awareness"""
    features = [0] * NUM_FEATURES

    if IP in packet:
        features[0] = len(packet)
        features[1] = packet[IP].tos
        features[2] = packet[IP].ttl
        features[3] = packet[IP].proto
        
        if TCP in packet:
            features[4] = packet[TCP].sport
            features[5] = packet[TCP].dport
            features[6] = packet[TCP].window
            features[7] = len(packet[TCP].payload)
            features[8] = packet[TCP].flags
        elif UDP in packet:
            features[4] = packet[UDP].sport
            features[5] = packet[UDP].dport
            features[7] = len(packet[UDP].payload)
            features[8] = 0  # No flags for UDP

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        features[9] = int(src_ip.split('.')[-1])
        features[10] = int(dst_ip.split('.')[-1])
        
        # QoS feature
        features[11] = packet[IP].tos & 0x1E

    return features

def classify_packet(packet):
    """Enhanced packet classification with detailed game detection"""
    if IP not in packet:
        return 'Normal', 1
    
    if TCP in packet:
        dport = packet[TCP].dport
        sport = packet[TCP].sport
        protocol = 'TCP'
    elif UDP in packet:
        dport = packet[UDP].dport
        sport = packet[UDP].sport
        protocol = 'UDP'
    else:
        return 'Normal', 1

    # Check for gaming traffic
    for port in [sport, dport]:
        if protocol in GAMING_PORTS and port in GAMING_PORTS[protocol]:
            return f'Gaming/{GAMING_PORTS[protocol][port]}', 5

    # Streaming traffic
    if dport in [1935, 443] or sport in [1935, 443]:
        return 'Streaming', 4

    # Real-time traffic
    if dport in [22, 53, 123, 5222] or sport in [22, 53, 123, 5222]:
        return 'Real Time', 4

    # Web traffic
    if dport in [80, 443] or sport in [80, 443]:
        # Check for streaming content in HTTPS
        if TCP in packet and dport == 443:
            if packet[TCP].payload:
                payload = str(packet[TCP].payload)
                if any(x in payload.lower() for x in ['video', 'stream', 'media']):
                    return 'Streaming', 4
        return 'Web', 3

    # Download traffic
    if dport in [21, 20, 990, 989, 8080, 3128] or sport in [21, 20, 990, 989, 8080, 3128]:
        return 'Download', 2

    return 'Normal', 1

def get_qos_priority(category, priority):
    """Convert classification to DSCP value for QoS"""
    qos_map = {
        5: 0x2E,  # Gaming (EF - Expedited Forwarding)
        4: 0x28,  # Streaming/Real-Time (AF41)
        3: 0x20,  # Web/Social Media (AF31)
        2: 0x18,  # Downloads (AF21)
        1: 0x00   # Normal (Default)
    }
    return qos_map.get(priority, 0x00)

def get_wireless_interfaces():
    try:
        # Use iwconfig to list wireless interfaces
        result = subprocess.run(['iwconfig'], capture_output=True, text=True)
        interfaces = []
        
        for line in result.stdout.split('\n'):
            if 'IEEE 802.11' in line:  # This indicates a wireless interface
                interface = line.split()[0]
                interfaces.append(interface)
        
        return interfaces
    except FileNotFoundError:
        # If iwconfig is not found, try ip link
        try:
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
            interfaces = []
            
            for line in result.stdout.split('\n'):
                if 'wlan' in line or 'wlp' in line:  # Common prefixes for wireless interfaces
                    interface = line.split(':')[1].strip()
                    interfaces.append(interface)
            
            return interfaces
        except Exception as e:
            print(f"Error getting wireless interfaces: {e}")
            return []

'''
def capture_packets(interface):
    """Capture and process network packets"""
    packet_buffer = deque(maxlen=SEQUENCE_LENGTH)
    features_list = []
    labels = []
    priorities = []
    start_time = time.time()

    def packet_callback(packet):
        nonlocal features_list, labels, priorities

        features = extract_features(packet)
        packet_buffer.append(features)

        if len(packet_buffer) == SEQUENCE_LENGTH:
            features_list.append(list(packet_buffer))
            category, priority = classify_packet(packet)
            labels.append(category)
            priorities.append(priority)

        if CAPTURE_DURATION and (time.time() - start_time > CAPTURE_DURATION):
            return True

    print(f"Capturing packets on {interface} for {CAPTURE_DURATION} seconds...")
    scapy.sniff(iface=interface, prn=packet_callback, store=False, 
                stop_filter=lambda p: packet_callback(p))

    return np.array(features_list), labels, priorities
'''

def capture_packets(interface):
    """Capture and process network packets"""
    packet_buffer = deque(maxlen=SEQUENCE_LENGTH)
    features_list = []
    labels = []
    priorities = []
    start_time = time.time()

    def packet_callback(packet):
        nonlocal features_list, labels, priorities

        features = extract_features(packet)
        packet_buffer.append(features)

        if len(packet_buffer) == SEQUENCE_LENGTH:
            features_list.append(np.array(packet_buffer))
            category, priority = classify_packet(packet)
            labels.append(category)
            priorities.append(priority)

        if CAPTURE_DURATION and (time.time() - start_time > CAPTURE_DURATION):
            return True

    print(f"Capturing packets on {interface} for {CAPTURE_DURATION} seconds...")
    scapy.sniff(iface=interface, prn=packet_callback, store=False, 
                stop_filter=lambda p: packet_callback(p))

    return np.array(features_list), labels, priorities

def main():
    # Check if running as root
    if os.geteuid() != 0:
        print("This script requires root privileges. Please run with sudo.")
        sys.exit(1)

    if OS_NAME != 'posix':
        print("This script is intended to run only on POSIX compliant system.")
        sys.exit(1)

    global CAPTURE_DURATION
    print("5 min = 300 sec\n10min = 600 sec\n1hr = 3600sec\n0sec = exit()")
    CAPTURE_DURATION = int(input("Enter Capture Duration in seconds: "))
    if CAPTURE_DURATION == 0:
        sys.exit(0)

    # Get available wireless interfaces
    wireless_interfaces = get_wireless_interfaces()
    
    if not wireless_interfaces:
        print("No wireless interfaces found. Please check your network connections.")
        return
    
    # If multiple interfaces found, let user choose
    if len(wireless_interfaces) > 1:
        print("\nAvailable wireless interfaces:")
        for i, iface in enumerate(wireless_interfaces):
            print(f"{i+1}. {iface}")
        choice = int(input("\nSelect interface number: ")) - 1
        interface = wireless_interfaces[choice]
    else:
        interface = wireless_interfaces[0]

    print(f"Using wireless interface: {interface}")
    
    X, y, priorities = capture_packets(interface)
    X_tensor = torch.from_numpy(X)
    y_list = y
    priorities_list = priorities
    # Generate timestamp
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    new_PT_FILENAME = f"datasets/packet_dataset_{timestamp}_{CAPTURE_DURATION}.pt"

    # Save the dataset
    torch.save((X_tensor, y_list, priorities_list), new_PT_FILENAME)
    
    print(f"Dataset saved as {new_PT_FILENAME} with shape: {X_tensor.shape}, labels: {len(y_list)}, priorities: {len(priorities_list)}")

if __name__ == "__main__":
    import os
    import sys
    main()