from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO, emit
import threading
import os
import datetime

app = Flask(__name__)
socketio = SocketIO(app)
logs = []
threat_ips = set()
monitoring = False
monitor_thread = None

def background_monitor():
    pass  # Placeholder

@app.route('/')
def index():
    total = len(logs)
    attack_count = sum(1 for log in logs if log['status'] == 'threat')
    safe_count = total - attack_count
    return render_template('index.html', logs=logs, total=total,
                           attack_count=attack_count, safe_count=safe_count)

@socketio.on('threat')
def handle_threat(data):
    ip = data['ip']
    status = data['status']
    reason = data.get('reason', 'Unknown activity')

    if not any(log['ip'] == ip and log['status'] == status for log in logs):
        detail = ""
        if status == 'threat':
            detail = f"⚠️ Detected: {reason}. Potential intrusion or scanning activity from {ip}."
        else:
            detail = f"✅ Safe: {reason}. Packet behavior aligned with normal traffic."

        logs.append({
            'ip': ip,
            'status': status,
            'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'reason': reason,
            'detail': detail
        })
        if status == 'threat':
            threat_ips.add(ip)
        emit('update', {'logs': logs}, broadcast=True)

@app.route('/block_ip', methods=['POST'])
def block_ip_route():
    ip = request.json.get('ip')
    if ip and ip not in threat_ips:
        threat_ips.add(ip)
        return jsonify({'result': f'IP {ip} blocked successfully.'})
    return jsonify({'result': 'Invalid IP or already blocked.'}), 400

@app.route('/download/<log_type>')
def download_log(log_type):
    filename = "malicious_log.txt" if log_type == "threat" else "safe_log.txt"
    path = os.path.join("logs", filename)
    if os.path.exists(path):
        return send_file(path, as_attachment=True)
    return "Log file not found", 404

@app.route('/start_monitoring', methods=['POST'])
def start_monitoring():
    global monitoring
    monitoring = True
    return jsonify({'result': 'Monitoring started.'})

@app.route('/stop_monitoring', methods=['POST'])
def stop_monitoring():
    global monitoring
    monitoring = False
    return jsonify({'result': 'Monitoring stopped.'})

if __name__ == '__main__':
    socketio.run(app, debug=True)
