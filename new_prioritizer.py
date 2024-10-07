
import ctypes
import sys

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    print("This script requires administrative privileges. Please run it as an administrator.")
    sys.exit(1)

# Rest of your code3.py content goes here

import win32process
import win32con
import win32api
import psutil
import winreg
from scapy.all import sniff, IP, TCP, UDP

def get_pid_by_port(port):
    for conn in psutil.net_connections():
        if conn.laddr.port == port:
            return conn.pid
    return None

def set_process_priority(pid, priority):
    try:
        handle = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, pid)
        priority_class = {
            "Games": win32process.REALTIME_PRIORITY_CLASS,
            "Real Time": win32process.REALTIME_PRIORITY_CLASS,
            "Streaming": win32process.HIGH_PRIORITY_CLASS,
            "Normal": win32process.NORMAL_PRIORITY_CLASS,
            "Web download": win32process.BELOW_NORMAL_PRIORITY_CLASS,
            "App download": win32process.IDLE_PRIORITY_CLASS
        }.get(priority, win32process.NORMAL_PRIORITY_CLASS)
        win32process.SetPriorityClass(handle, priority_class)
    except Exception:
        pass
    finally:
        if 'handle' in locals():
            win32api.CloseHandle(handle)

def get_wifi_interface_name():
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards") as key:
            index = 0
            while True:
                try:
    
                    subkey_name = winreg.EnumKey(key, index)
                    with winreg.OpenKey(key, subkey_name) as subkey:
                        description = winreg.QueryValueEx(subkey, "Description")[0]
                        if "Wi-Fi" in description:
                            return winreg.QueryValueEx(subkey, "ServiceName")[0]
                    index += 1
                except WindowsError:
                    break
    except WindowsError:
        pass
    return None

def capture_packets(prediction_queue):
    wifi_interface = get_wifi_interface_name()
    if not wifi_interface:
        return

    def packet_callback(packet):
        if IP in packet:
            src_ip = packet[IP].src
            if TCP in packet:
                src_port, dst_port = packet[TCP].sport, packet[TCP].dport
            elif UDP in packet:
                src_port, dst_port = packet[UDP].sport, packet[UDP].dport
            else:
                return

            while not prediction_queue.empty():
                prediction = prediction_queue.get()
                if (prediction['src_ip'] == src_ip and
                    prediction['src_port'] == src_port and
                    prediction['dst_port'] == dst_port):
                    pid = get_pid_by_port(src_port)
                    if pid:
                        set_process_priority(pid, prediction['priority'])
                    break
                prediction_queue.put(prediction)

    sniff(prn=packet_callback, store=0, iface=wifi_interface)

def priority_setter(prediction_queue):
    capture_packets(prediction_queue)

if __name__ == "__main__":
    import multiprocessing as mp
    from new_deploy_model import main as code1_main
    
    prediction_queue = mp.Queue()
    
    code1_process = mp.Process(target=code1_main, args=(None,))
    code1_process.start()
    
    priority_setter(prediction_queue)