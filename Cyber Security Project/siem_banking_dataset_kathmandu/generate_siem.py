import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import hashlib
import uuid

print("="*70)
print("SIEM LOG DATASET GENERATOR - KATHMANDU VALLEY BANKS")
print("="*70)

np.random.seed(42)
random.seed(42)

# Configuration - Reduced for efficiency
TOTAL_LOGS = 500000  # 500K logs
THREAT_RATIO = 0.05

# Banks
BANKS = ['NICASIA', 'NABIL', 'GBIME', 'SBL', 'PRABHU', 'MEGA', 'SANIMA']

# Threats with MITRE
THREATS = {
    'BRUTE_FORCE': {'severity': 'high', 'mitre': 'T1110'},
    'PHISHING': {'severity': 'medium', 'mitre': 'T1566'},
    'MALWARE': {'severity': 'critical', 'mitre': 'T1204'},
    'PORT_SCAN': {'severity': 'medium', 'mitre': 'T1046'},
    'SQL_INJECTION': {'severity': 'high', 'mitre': 'T1190'},
    'DATA_EXFIL': {'severity': 'critical', 'mitre': 'T1048'},
    'SWIFT_FRAUD': {'severity': 'critical', 'mitre': 'T1657'},
    'ATM_ATTACK': {'severity': 'critical', 'mitre': 'T1657'},
    'INSIDER_THREAT': {'severity': 'critical', 'mitre': 'T1078'},
    'ACCOUNT_TAKEOVER': {'severity': 'high', 'mitre': 'T1078'},
    'DDOS': {'severity': 'high', 'mitre': 'T1498'},
    'RANSOMWARE': {'severity': 'critical', 'mitre': 'T1486'},
    'LATERAL_MOVEMENT': {'severity': 'critical', 'mitre': 'T1021'},
}

MAL_IPS = ['185.220.101.', '45.155.205.', '103.75.118.', '5.188.206.']
NP_IPS = ['202.52.', '202.70.', '116.66.', '182.93.']

def gen_ip(mal=False):
    if mal:
        return random.choice(MAL_IPS) + str(random.randint(1, 254))
    if random.random() < 0.6:
        return random.choice(NP_IPS) + f"{random.randint(1,254)}.{random.randint(1,254)}"
    return f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"

def gen_user():
    f = random.choice(['ram', 'shyam', 'hari', 'krishna', 'sita', 'prakash', 'santosh', 'rajesh'])
    l = random.choice(['sharma', 'thapa', 'gurung', 'shrestha', 'maharjan', 'pradhan', 'joshi'])
    return f"{f}.{l}"

def gen_ts():
    base = datetime.now() - timedelta(days=random.randint(0, 30))
    return base.replace(hour=random.randint(0, 23), minute=random.randint(0, 59), second=random.randint(0, 59))

# Generate logs
print(f"\nGenerating {TOTAL_LOGS:,} logs...")

logs = []
sources = ['firewall', 'auth', 'core_banking', 'web', 'endpoint', 'database', 'ids', 'email', 'atm', 'swift']
threat_types = list(THREATS.keys())

for i in range(TOTAL_LOGS):
    is_threat = random.random() < THREAT_RATIO
    source = random.choice(sources)
    threat_type = random.choice(threat_types) if is_threat else None
    ts = gen_ts()
    
    log = {
        'log_id': f"LOG{i:010d}",
        'timestamp': ts.isoformat(),
        'log_source': source,
        'src_ip': gen_ip(is_threat),
        'dst_ip': gen_ip(),
        'src_port': random.randint(1024, 65535),
        'dst_port': random.choice([22, 80, 443, 1433, 3389, 8080]),
        'protocol': random.choice(['TCP', 'UDP']),
        'action': 'deny' if is_threat else random.choice(['allow', 'deny']),
        'bytes_sent': random.randint(100, 1000000 if is_threat else 100000),
        'bytes_recv': random.randint(100, 50000),
        'username': gen_user(),
        'user_role': random.choice(['TELLER', 'SUPERVISOR', 'IT_ADMIN', 'DBA', 'SWIFT_OP']),
        'event_type': random.choice(['logon', 'transaction', 'query', 'alert', 'access']),
        'status': 'failure' if is_threat and random.random() > 0.3 else 'success',
        'device': f"{random.choice(BANKS)}-{source.upper()}-{random.randint(1,10):02d}",
        'severity': THREATS.get(threat_type, {}).get('severity', 'info') if is_threat else random.choice(['info', 'low']),
        'is_threat': 1 if is_threat else 0,
        'threat_type': threat_type,
        'mitre_id': THREATS.get(threat_type, {}).get('mitre') if is_threat else None,
    }
    logs.append(log)
    
    if (i + 1) % 100000 == 0:
        print(f"  Progress: {(i+1)/TOTAL_LOGS*100:.0f}% ({i+1:,}/{TOTAL_LOGS:,})")

print(f"\n✓ Generated {len(logs):,} logs")

# Create DataFrame
df = pd.DataFrame(logs)
df = df.sort_values('timestamp').reset_index(drop=True)

# Stats
print(f"\n📊 Total: {len(df):,}")
print(f"📊 Threats: {df['is_threat'].sum():,} ({df['is_threat'].mean()*100:.1f}%)")
print(f"\n📁 Sources:\n{df['log_source'].value_counts().to_string()}")
print(f"\n⚠️ Threat Types:\n{df[df['is_threat']==1]['threat_type'].value_counts().to_string()}")

# Save
df.to_csv('/home/claude/siem_logs_full.csv', index=False)
print(f"\n✓ Saved: siem_logs_full.csv")

df[df['is_threat']==1].to_csv('/home/claude/siem_threats.csv', index=False)
print(f"✓ Saved: siem_threats.csv")

# Balanced training
threats = df[df['is_threat']==1]
normals = df[df['is_threat']==0].sample(len(threats)*3)
balanced = pd.concat([threats, normals]).sample(frac=1)
balanced.to_csv('/home/claude/siem_balanced.csv', index=False)
print(f"✓ Saved: siem_balanced.csv ({len(balanced):,} records)")

print("\n" + "="*70)
print("COMPLETE!")
print("="*70)
