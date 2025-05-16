import scapy.all as scapy
import joblib
import socketio
import datetime
import subprocess
import os
import warnings
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")

model = joblib.load("models/rf_model.pkl")
scaler = joblib.load("models/scaler.pkl")

sio = socketio.Client()
try:
    sio.connect('http://localhost:5000')
except:
    print("[WARNING] Could not connect to dashboard")

threat_ips = set()

def extract_features(packet):
    return [
        packet.time,
        len(packet),
        packet.ttl if hasattr(packet, "ttl") else 0,
        1 if packet.haslayer(scapy.TCP) else 0,
        1 if packet.haslayer(scapy.UDP) else 0,
        1 if packet.haslayer(scapy.ICMP) else 0
    ]

def log_to_file(ip, label, reason):
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if label == "attack":
        with open(os.path.join(log_dir, "malicious_log.txt"), "a") as f:
            f.write(f"{timestamp} | IP: {ip} | Threat: {reason}\n")
    else:
        with open(os.path.join(log_dir, "safe_log.txt"), "a") as f:
            f.write(f"{timestamp} | IP: {ip} | Status: Safe | Reason: Normal behavior\n")

def block_ip(ip):
    try:
        cmd = [
            "powershell", 
            "New-NetFirewallRule", 
            "-DisplayName", f"Block_{ip}", 
            "-Direction", "Inbound", 
            "-RemoteAddress", ip, 
            "-Action", "Block"
        ]
        subprocess.run(cmd, check=True)
        print(f"[BLOCK] 🔒 Blocking IP: {ip}")
    except Exception as e:
        print(f"[ERROR] Could not block IP {ip}: {e}")

def process_packet(packet):
    if not packet.haslayer(scapy.IP):
        return
    src_ip = packet[scapy.IP].src
    features = extract_features(packet)

    try:
        scaled = scaler.transform([features[1:]])  # Exclude timestamp
        prediction = model.predict(scaled)[0]

        if prediction == "attack":
            reason = "Unusual packet behavior detected"
            if src_ip not in threat_ips:
                print(f"[ALERT] 🚨 Threat detected from IP: {src_ip}")
                log_to_file(src_ip, "attack", reason)
                sio.emit('threat', {'ip': src_ip, 'status': 'threat', 'reason': reason})
                block_ip(src_ip)
                threat_ips.add(src_ip)
        else:
            print(f"[INFO] ✅ Safe packet detected")
            log_to_file(src_ip, "safe", "")
            sio.emit('threat', {'ip': src_ip, 'status': 'safe', 'reason': "Normal behavior"})
    except Exception as e:
        print(f"[ERROR] Prediction issue: {e}")

print("[INFO] 🧠 Monitoring started... Press Ctrl+C to stop.")
scapy.sniff(prn=process_packet, store=False)
