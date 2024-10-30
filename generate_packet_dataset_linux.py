import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
import torch
import numpy as np
from collections import deque
import time
import subprocess
import datetime
from os import name as OS_NAME

# Constants
SEQUENCE_LENGTH = 5
NUM_FEATURES = 10
CAPTURE_DURATION = None  # Will be set by user input

def extract_features(packet):
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
        elif UDP in packet:
            features[4] = packet[UDP].sport
            features[5] = packet[UDP].dport
            features[7] = len(packet[UDP].payload)

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        features[8] = int(src_ip.split('.')[-1])  # Last octet of source IP
        features[9] = int(dst_ip.split('.')[-1])  # Last octet of destination IP

    return features

def classify_packet(packet):
    if IP in packet:
        if TCP in packet:
            dport = packet[TCP].dport
            sport = packet[TCP].sport
        elif UDP in packet:
            dport = packet[UDP].dport
            sport = packet[UDP].sport
        else:
            return 'Normal'  # Neither TCP nor UDP

        if dport == 53 or sport == 53:  # DNS
            return 'Real Time'
        elif dport in [80, 443]:  # HTTP/HTTPS
            return 'Web download'
        elif dport in [3074, 3075]:  # Xbox Live
            return 'Games'
        elif dport in [1935, 1936, 5222]:  # RTMP, XMPP
            return 'Streaming'
        elif dport == 22:  # SSH
            return 'Real Time'
        elif dport in [123]:  # NTP
            return 'Real Time'
    
    return 'Normal'  # Default classification

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

def capture_packets(interface):
    packet_buffer = deque(maxlen=SEQUENCE_LENGTH)
    features_list = []
    labels = []
    start_time = time.time()

    def packet_callback(packet):
        nonlocal features_list, labels

        features = extract_features(packet)
        packet_buffer.append(features)

        if len(packet_buffer) == SEQUENCE_LENGTH:
            features_list.append(list(packet_buffer))
            labels.append(classify_packet(packet))

        if CAPTURE_DURATION and (time.time() - start_time > CAPTURE_DURATION):
            return True  # Stop capture

    print(f"Capturing packets on {interface} for {CAPTURE_DURATION} seconds...")
    scapy.sniff(iface=interface, prn=packet_callback, store=False, stop_filter=lambda p: packet_callback(p))

    return np.array(features_list), labels

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
    
    X, y = capture_packets(interface)
    
    # Convert to PyTorch tensors
    X_tensor = torch.FloatTensor(X)
    y_list = y  # Keep y as a list of strings

    # Generate timestamp
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    new_PT_FILENAME = f"datasets/packet_dataset_{timestamp}_{CAPTURE_DURATION}.pt"

    # Save the dataset
    torch.save((X_tensor, y_list), f'packet_dataset_{timestamp}_{CAPTURE_DURATION}.pt')
    
    print(f"Dataset saved. Shape: {X_tensor.shape}, Labels: {len(y_list)}")

if __name__ == "__main__":
    import os
    import sys
    main()