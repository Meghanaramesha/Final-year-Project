import pandas as pd
import numpy as np
import os
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

# Change to your actual dataset path
DATA_PATH = "datasets/KDDTrain+.txt"
MODEL_DIR = "models"
MODEL_PATH = os.path.join(MODEL_DIR, "rf_model.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")

# Define columns as per dataset (you can keep all for loading)
columns = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root',
    'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
    'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty_level'
]

print("🔽 Loading dataset...")
df = pd.read_csv(DATA_PATH, names=columns)

# Drop difficulty_level
df.drop('difficulty_level', axis=1, inplace=True)

# Binary classification
df['label'] = df['label'].apply(lambda x: 'normal' if x == 'normal' else 'attack')

# Encode protocol_type: tcp=0, udp=1, icmp=2, other=3
df['protocol_type'] = df['protocol_type'].map({'tcp': 0, 'udp': 1, 'icmp': 2}).fillna(3).astype(int)

# Create new feature set with only the 6 features we can extract live
X = pd.DataFrame()
X['protocol_type'] = df['protocol_type']
X['packet_length'] = df['src_bytes'] + df['dst_bytes']  # total bytes as proxy for packet size
X['ttl'] = 64  # NSL-KDD does not have TTL, so we fix dummy 64
X['src_port'] = 0  # no port info in dataset; set 0 or fill with count
X['dst_port'] = 0
X['flags'] = 0  # dummy zero for flags count

y = df['label']

print("🧠 Scaling and splitting data...")
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42
)

print("🧠 Training model...")
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

y_pred = clf.predict(X_test)
print("✅ Model Evaluation:\n")
print(classification_report(y_test, y_pred))

os.makedirs(MODEL_DIR, exist_ok=True)
joblib.dump(clf, MODEL_PATH)
joblib.dump(scaler, SCALER_PATH)
print(f"\n💾 Model and scaler saved to '{MODEL_DIR}' folder.")
