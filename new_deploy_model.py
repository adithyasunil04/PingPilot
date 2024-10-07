from sys import argv
import os
import numpy as np
import onnxruntime as ort
from pathlib import Path
from scapy.all import sniff, IP, TCP, UDP
import threading
import queue
from new_prioritizer import priority_setter

def load_quantized_model(model_path, ep='ipu'):
    try:
        providers = ['VitisAIExecutionProvider']
        cache_dir = Path(__file__).parent.resolve()
        provider_options = [{
            'config_file': 'vaip_config.json',
            'cacheDir': str(cache_dir),
            'cacheKey': 'modelcachekey'
        }]
        return ort.InferenceSession(model_path, providers=providers, provider_options=provider_options)
    except Exception as e:
        print(f"Error loading model: {e}")
        return None

def extract_features(src_ip, src_port, dst_port):
    features = np.array([int(x) for x in src_ip.split('.')] + [src_port, dst_port])
    if len(features) < 10:
        features = np.pad(features, (0, 10 - len(features)))
    elif len(features) > 10:
        features = features[:10]
    return features.reshape(1, 10, 1).repeat(10, axis=2).astype(np.float32)

def get_priority(prediction):
    class_to_priority = {0: "Games", 1: "Real Time", 2: "Streaming", 3: "Normal", 4: "Web download", 5: "App download"}
    return class_to_priority[np.argmax(prediction[0])]

def packet_callback(packet, packet_queue):
    if IP in packet:
        src_ip = packet[IP].src
        if TCP in packet:
            src_port, dst_port = packet[TCP].sport, packet[TCP].dport
        elif UDP in packet:
            src_port, dst_port = packet[UDP].sport, packet[UDP].dport
        else:
            return
        packet_queue.put((src_ip, src_port, dst_port))

def process_packets(session, packet_queue, prediction_queue, stop_event):
    while not stop_event.is_set():
        try:
            src_ip, src_port, dst_port = packet_queue.get(timeout=1)
            features = extract_features(src_ip, src_port, dst_port)
            prediction = session.run(None, {'input': features})
            priority = get_priority(prediction)
            prediction_queue.put({"src_ip": src_ip, "src_port": src_port, "dst_port": dst_port, "priority": priority})
        except queue.Empty:
            continue
        except Exception as e:
            print(f"Error processing packet: {e}")

def main(model_path):
    if model_path is None or not os.path.isfile(model_path):
        model_path = input("Enter the quantized model (.onnx) file name: ")
        if not os.path.isfile(model_path):
            print("Invalid file path.")
            return

    session = load_quantized_model(model_path)
    if session is None:
        return

    packet_queue = queue.Queue()
    prediction_queue = queue.Queue()
    stop_event = threading.Event()

    packet_thread = threading.Thread(target=process_packets, args=(session, packet_queue, prediction_queue, stop_event))
    packet_thread.start()

    priority_thread = threading.Thread(target=priority_setter, args=(prediction_queue, stop_event))
    priority_thread.start()

    try:
        sniff(prn=lambda x: packet_callback(x, packet_queue), store=0)
    except KeyboardInterrupt:
        print("Stopping...")
    finally:
        stop_event.set()
        packet_thread.join()
        priority_thread.join()

if __name__ == "__main__":
    main(argv[1] if len(argv) > 1 else None)