import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
import torch
import numpy as np
from collections import deque
import time
import subprocess
import datetime
from os import name

# Constants
SEQUENCE_LENGTH = 5
NUM_FEATURES = 10
CAPTURE_DURATION = None  # Capture for 3 hrs
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
def get_wifi_interface():
    try:
        # Run netsh command to get WiFi interface information
        result = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True)
        output = result.stdout

        # Parse the output to find the name of the connected WiFi interface
        for line in output.split('\n'):
            if "Name" in line:
                return line.split(':')[1].strip()
    except Exception as e:
        print(f"Error getting WiFi interface: {e}")
    return None

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

        if time.time() - start_time > CAPTURE_DURATION:
            return True  # Stop capture

    print(f"Capturing packets on {interface} for {CAPTURE_DURATION} seconds...")
    scapy.sniff(iface=interface, prn=packet_callback, store=False, stop_filter=lambda p: packet_callback(p))

    return np.array(features_list), labels

def main():

    global CAPTURE_DURATION
    print("5 min = 300 sec\n10min = 600 sec\n1hr = 3600sec\n")
    CAPTURE_DURATION = int(input("Enter Capture Duration in seconds:"))

    interface = get_wifi_interface()
    if not interface:
        print("Could not find WiFi interface. Please check your network connections.")
        return

    print(f"Using WiFi interface: {interface}")
    
    X, y = capture_packets(interface)
    
    # Convert to PyTorch tensors
    X_tensor = torch.FloatTensor(X)
    y_list = y  # Keep y as a list of strings
    

     # Generate timestamp
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    if name=="posix":
        new_PT_FILENAME = f"datasets/packet_dataset_{timestamp}_{CAPTURE_DURATION}.pt"
    elif name == "nt":
        new_PT_FILENAME = f"datasets\\packet_dataset_{timestamp}_{CAPTURE_DURATION}.pt"


    # Save the dataset
    torch.save((X_tensor, y_list), new_PT_FILENAME)
    
    print(f"Dataset saved. Shape: {X_tensor.shape}, Labels: {len(y_list)}")

if __name__ == "__main__":
    main()