✅ AI-Powered Cybersecurity System

✅ Copy & Save the following content into your project folder as README.md:
markdown
Copy
Edit
# 🛡️ AI-Powered Cybersecurity System

An intelligent and scalable AI-driven system designed to monitor real-time network traffic, detect cybersecurity threats, and automatically block malicious IP addresses — all with a user-friendly dashboard.

![Project Dashboard](assets/dashboard-screenshot.png)

---

## 📌 Project Features

✅ Real-time network traffic monitoring  
✅ AI/ML-based threat detection using Random Forest  
✅ Auto IP blocking via PowerShell Firewall Rules  
✅ Interactive dashboard with:
- Live packet logs
- Pie chart of safe vs threat
- IP blocking buttons
✅ Start/Stop monitoring from the web UI  
✅ Logging of all events (safe and malicious) with timestamps and reasons  
✅ Downloadable log files  
✅ IEEE-referenced architecture and flow

---

## ⚙️ Tech Stack

| Layer        | Technology                |
|--------------|----------------------------|
| Language     | Python 3.11                |
| ML Model     | RandomForestClassifier (scikit-learn) |
| Web Framework| Flask + Flask-SocketIO     |
| UI           | HTML5, CSS, JavaScript     |
| Network      | Scapy                      |
| Visuals      | Chart.js                   |
| Firewall     | Windows PowerShell         |
| Dataset      | NSL-KDD (KDDTrain+.txt)    |

---

## 📂 Folder Structure

ai-cybersecurity-ml/
│
├── dashboard/ # Flask web app
│ ├── app.py
│ └── templates/
│ └── index.html
│
├── datasets/
│ └── KDDTrain+.txt # NSL-KDD training data
│
├── models/
│ ├── rf_model.pkl
│ └── scaler.pkl
│
├── scripts/
│ ├── train_model.py # ML training
│ └── network_monitoring.py # Real-time monitoring
│
├── logs/
│ ├── safe_log.txt
│ └── malicious_log.txt
│
├── requirements.txt
└── README.md

yaml
Copy
Edit

---

## 🚀 How to Run This Project

### 1️⃣ Clone Repository
```bash
git clone https://github.com/Meghanaramesha/Final-year-Project.git
cd Final-year-Project
2️⃣ Install Dependencies
bash
Copy
Edit
pip install -r requirements.txt
3️⃣ Train Model
bash
Copy
Edit
python scripts/train_model.py
4️⃣ Start Dashboard
bash
Copy
Edit
python dashboard/app.py
5️⃣ Start Monitoring (New Terminal)
bash
Copy
Edit
python scripts/network_monitoring.py
🎯 Why This Project is Important
Real-time protection against evolving cyber threats

Uses ML instead of hardcoded rules (scalable & adaptive)

Can be integrated into corporate firewalls or SOCs

Demonstrates practical cybersecurity automation using AI

Ideal for Smart India Hackathon, Final Year Projects & IEEE-based research

📊 Flow Diagram
plaintext
Copy
Edit
+----------------+        +-----------------+        +-------------------+
|  Live Packets  | ---->  | Feature Extract | ---->  | ML Model (RF)     |
+----------------+        +-----------------+        +--------+----------+
                                                        |  Safe / Threat
                                                        ↓
                                               +-----------------------+
                                               | Flask + Dashboard     |
                                               +-----------------------+
                                               | Block IP | Chart | Log|
🧠 IEEE Reference Papers
AI-based Intrusion Detection — IEEE Access, 2022

NSL-KDD for Benchmarking IDS — Canadian Institute for Cybersecurity

Machine Learning in Cybersecurity — IEEE 2023 Review Paper
(You can upload these PDF references in the /docs folder)

