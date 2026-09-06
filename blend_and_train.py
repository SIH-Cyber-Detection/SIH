import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib

features = [
    'Total_Packets', 'Total_Bytes', 'Src2Dst_Ratio',
    'Flow Duration', 'Flow Bytes/s', 'Flow Packets/s',
    'Packet Length Mean', 'Packet Length Std',
    'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count',
    'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
    'Min Packet Length'
]

print("[*] Loading CIC-IDS-2017 Enterprise Baseline...")
df_base = pd.read_csv("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
df_base.columns = df_base.columns.str.strip()

# Engineer the identical 15 features
df_base['Total_Packets'] = df_base['Total Fwd Packets'] + df_base['Total Backward Packets']
df_base['Total_Bytes'] = df_base['Total Length of Fwd Packets'] + df_base['Total Length of Bwd Packets']
df_base['Src2Dst_Ratio'] = np.where(df_base['Total_Bytes'] > 0, df_base['Total Length of Fwd Packets'] / df_base['Total_Bytes'], 0.0)
df_base = df_base[features + ['Label']].copy()

print("[*] Loading Synthetic Local Attack Flows...")
try:
    df_synth = pd.read_csv("synthetic_attacks.csv")[features + ['Label']].copy()
    # Oversample the dense local footprint so its mathematical weight is not erased
    df_synth = pd.concat([df_synth] * 5000, ignore_index=True)
except FileNotFoundError:
    print("[!] synthetic_attacks.csv missing. Run extract_synthetic.py first.")
    exit(1)

# Separate Classes
df_benign = df_base[df_base['Label'] == 'BENIGN'].copy()
df_attacks_base = df_base[df_base['Label'] != 'BENIGN'].copy()

# The Blending Logic: Downsample enterprise attacks to match the benign count to prevent class imbalance,
# then aggressively inject the synthetic local attacks so the model learns the localhost footprint.
target_size = len(df_benign)
if len(df_attacks_base) > target_size:
    df_attacks_base = df_attacks_base.sample(n=target_size - len(df_synth), random_state=42)

df_blended = pd.concat([df_benign, df_attacks_base, df_synth], ignore_index=True)
df_blended.replace([np.inf, -np.inf], np.nan, inplace=True)
df_blended.dropna(inplace=True)

X = df_blended[features]
y = df_blended['Label']

print(f"[*] Blended Dataset Dimensions: {len(X)} samples.")
print(f"[*] Benign Samples: {len(df_benign)}")
print(f"[*] Malicious Samples: {len(df_attacks_base) + len(df_synth)}")

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

print("[*] Training Blended Random Forest...")
rf = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=-1)
rf.fit(X_train, y_train)

print("\n--- Classification Report ---")
print(classification_report(y_test, rf.predict(X_test)))

joblib.dump(rf, "engine_a_rf.joblib")
print("[+] Model saved to engine_a_rf.joblib")