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
        # Steam and Source Engine Games
        27015: 'Steam', 27016: 'Steam', 27017: 'Steam', 27018: 'Steam', 27019: 'Steam',
        # CSGO
        27020: 'CSGO', 27021: 'CSGO',
        # Valorant
        8393: 'Valorant', 8394: 'Valorant',
        # Xbox Live
        3074: 'Xbox Live',
        # PUBG
        24000: 'PUBG', 24001: 'PUBG', 24002: 'PUBG',
        # Call of Duty
        27014: 'Call of Duty', 27015: 'Call of Duty',
        # Rainbow Six Siege
        10000: 'R6 Siege', 10001: 'R6 Siege', 10002: 'R6 Siege',
        # Fortnite
        5222: 'Fortnite', 5795: 'Fortnite', 5847: 'Fortnite',
        # Minecraft
        25565: 'Minecraft', 25575: 'Minecraft',
        # League of Legends
        2099: 'League of Legends', 5000: 'League of Legends', 
        5223: 'League of Legends', 8393: 'League of Legends',
        8394: 'League of Legends', 8088: 'League of Legends'
    },
    'UDP': {
        # Steam and Source Engine Games
        27015: 'Steam', 27016: 'Steam', 27017: 'Steam', 27018: 'Steam', 27019: 'Steam',
        # CSGO
        27020: 'CSGO', 27021: 'CSGO',
        # Valorant
        8401: 'Valorant',
        # Console Gaming
        3074: 'Xbox Live', 3075: 'PSN',
        # PUBG
        24000: 'PUBG', 24001: 'PUBG', 24002: 'PUBG',
        # Call of Duty
        3075: 'Call of Duty', 3076: 'Call of Duty', 
        3077: 'Call of Duty', 3078: 'Call of Duty',
        # Rainbow Six Siege
        10000: 'R6 Siege', 10001: 'R6 Siege', 10002: 'R6 Siege',
        # Fortnite
        5222: 'Fortnite', 5795: 'Fortnite', 5847: 'Fortnite',
        9000: 'Fortnite', 9001: 'Fortnite',
        # Minecraft
        19132: 'Minecraft Bedrock', 25565: 'Minecraft Java',
        # League of Legends
        5000: 'League of Legends', 5100: 'League of Legends',
        8393: 'League of Legends', 8394: 'League of Legends',
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

def get_wifi_interface():
    """Get the active WiFi interface name"""
    try:
        result = subprocess.run(["netsh", "wlan", "show", "interfaces"], 
                              capture_output=True, text=True)
        output = result.stdout

        for line in output.split('\n'):
            if "Name" in line:
                return line.split(':')[1].strip()
    except Exception as e:
        print(f"Error getting WiFi interface: {e}")
    return None

def capture_packets(interface):
    """Capture and process network packets"""
    packet_buffer = deque(maxlen=SEQUENCE_LENGTH)
    features_list = []
    labels = []
    categories = []
    priorities = []
    start_time = time.time()

    def packet_callback(packet):
        nonlocal features_list, labels, categories, priorities

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

def main():
    if OS_NAME != "nt":
        print("This script is intended to run only on Windows 10/11")
        sys.exit(1)

    global CAPTURE_DURATION
    print("5 min = 300 sec\n10min = 600 sec\n1hr = 3600sec\n0sec = exit()")
    CAPTURE_DURATION = int(input("Enter Capture Duration in seconds:"))

    if CAPTURE_DURATION == 0:
        sys.exit(0)
    
    interface = get_wifi_interface()
    if not interface:
        print("Could not find WiFi interface. Please check your network connections.")
        return

    print(f"Using WiFi interface: {interface}")
    
    X, labels, priorities = capture_packets(interface)
    
    # Convert to PyTorch tensors
    X_tensor = torch.FloatTensor(X)
    
    # Generate timestamp
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    new_PT_FILENAME = f"datasets\\packet_dataset_{timestamp}.pt"

    # Save the dataset with enhanced labels
    torch.save({
        'features': X_tensor,
        'labels': labels,
        'priorities': priorities,
        'timestamp': timestamp
    }, new_PT_FILENAME)
    
    print(f"Dataset saved to {new_PT_FILENAME}")
    print(f"Shape: {X_tensor.shape}, Labels: {len(labels)}")
    
    # Print statistics
    categories = set(labels)
    print("\nTraffic Distribution:")
    for category in categories:
        count = labels.count(category)
        percentage = (count / len(labels)) * 100
        print(f"{category}: {count} packets ({percentage:.2f}%)")

if __name__ == "__main__":
    main()