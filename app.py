import streamlit as st
import joblib
import pandas as pd
import numpy as np
import datetime
from io import BytesIO

# ---------------------------
# 1. Config & Page Setup
# ---------------------------
st.set_page_config(
    page_title="SOC Dashboard: IDS Mitigation",
    page_icon="🚨",
    layout="wide"
)

# ---------------------------
# 2. Define Features & Playbook
# ---------------------------

# Input Features (Harus persis sama dengan training data model)
SELECTED_FEATURES = [
    'Dst Port', 'Protocol',
    'Flow Duration', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max',
    'Fwd Pkt Len Mean', 'Bwd Pkt Len Mean', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
    'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt',
    'Flow Byts/s', 'Flow Pkts/s'
]

# SOC Playbook Logic (Mitigation Rules)
def get_mitigation_plan(attack_type, target_ip="192.168.1.X"):
    """
    Returns action, script, and command based on attack type.
    """
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Default (Safe)
    plan = {
        "severity": "Low",
        "action": "Monitor",
        "script": "N/A",
        "command": "N/A",
        "alert": "Traffic appears normal."
    }

    # Logic Mapping
    if "Bot" in attack_type:
        plan = {
            "severity": "High",
            "action": "Alert SOC L1",
            "script": "general_triage.sh",
            "command": f"Isolate Host {target_ip}",
            "alert": "Botnet activity detected. Machine may be compromised."
        }
    elif "DDoS" in attack_type or "LOIC" in attack_type or "HOIC" in attack_type:
        plan = {
            "severity": "Critical",
            "action": "Block Traffic",
            "script": "ddos_mitigation.sh",
            "command": f"iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT",
            "alert": "High volume DDoS attack detected. Immediate throttling required."
        }
    elif "BruteForce" in attack_type or "FTP" in attack_type:
        plan = {
            "severity": "Medium",
            "action": "Block Source IP",
            "script": "brute_force_check.py",
            "command": f"iptables -A INPUT -s {target_ip} -j DROP",
            "alert": "Repeated login failures detected."
        }
    elif "Benign" in attack_type or "Normal" in attack_type:
        plan["severity"] = "Safe"
    
    return plan, current_time

# Fungsi Helper: Generate Template CSV (Lebih stabil daripada Excel)
def generate_csv_template():
    df_template = pd.DataFrame(columns=SELECTED_FEATURES)
    # Dummy row example
    example_row = {
        'Dst Port': 80, 'Protocol': 6,
        'Flow Duration': 1000, 'Flow IAT Mean': 50.0, 'Flow IAT Std': 10.0, 'Flow IAT Max': 100.0,
        'Fwd Pkt Len Mean': 50.0, 'Bwd Pkt Len Mean': 60.0, 'Tot Fwd Pkts': 10, 'Tot Bwd Pkts': 8,
        'FIN Flag Cnt': 0, 'SYN Flag Cnt': 1, 'RST Flag Cnt': 0, 'PSH Flag Cnt': 0, 'ACK Flag Cnt': 1,
        'Flow Byts/s': 1000.0, 'Flow Pkts/s': 20.0
    }
    df_template = pd.concat([df_template, pd.DataFrame([example_row])], ignore_index=True)
    # Return CSV string encoded
    return df_template.to_csv(index=False).encode('utf-8')

# Fungsi Helper: Generate Data Dummy Random CSV
def generate_dummy_csv(num_rows=50):
    data = {
        'Dst Port': np.random.choice([80, 443, 21, 22, 53, 8080], num_rows),
        'Protocol': np.random.choice([6, 17], num_rows),
        'Flow Duration': np.random.randint(100, 100000, num_rows),
        'Flow IAT Mean': np.random.uniform(1.0, 5000.0, num_rows),
        'Flow IAT Std': np.random.uniform(0.0, 1000.0, num_rows),
        'Flow IAT Max': np.random.uniform(100.0, 10000.0, num_rows),
        'Fwd Pkt Len Mean': np.random.uniform(0.0, 500.0, num_rows),
        'Bwd Pkt Len Mean': np.random.uniform(0.0, 1000.0, num_rows),
        'Tot Fwd Pkts': np.random.randint(1, 100, num_rows),
        'Tot Bwd Pkts': np.random.randint(0, 100, num_rows),
        'FIN Flag Cnt': np.random.choice([0, 1], num_rows, p=[0.9, 0.1]),
        'SYN Flag Cnt': np.random.choice([0, 1], num_rows, p=[0.5, 0.5]),
        'RST Flag Cnt': np.random.choice([0, 1], num_rows, p=[0.9, 0.1]),
        'PSH Flag Cnt': np.random.choice([0, 1], num_rows, p=[0.7, 0.3]),
        'ACK Flag Cnt': np.random.choice([0, 1], num_rows, p=[0.3, 0.7]),
        'Flow Byts/s': np.random.uniform(0.0, 100000.0, num_rows),
        'Flow Pkts/s': np.random.uniform(0.0, 5000.0, num_rows),
    }
    df_dummy = pd.DataFrame(data)
    df_dummy = df_dummy[SELECTED_FEATURES]
    
    return df_dummy.to_csv(index=False).encode('utf-8')

# ---------------------------
# 3. Load Model (UPDATED: Handle Dictionary Structure)
# ---------------------------
@st.cache_resource
def load_model():
    try:
        # Load object dari file pickle
        loaded_object = joblib.load('ids_model_final.pkl')
        
        # Cek apakah object adalah dictionary (sering terjadi jika save metadata)
        if isinstance(loaded_object, dict):
            # Coba cari key umum yang biasa digunakan untuk menyimpan model
            possible_keys = ['model', 'classifier', 'pipeline', 'estimator', 'xgb_model']
            for key in possible_keys:
                if key in loaded_object:
                    return loaded_object[key]
            
            # Jika key tidak ditemukan, kembalikan error spesifik
            st.error(f"⚠️ File pickle adalah dictionary, tapi tidak ditemukan key model. Keys yang ada: {list(loaded_object.keys())}")
            return None
            
        return loaded_object
        
    except FileNotFoundError:
        return None
    except Exception as e:
        st.error(f"Error loading model: {e}")
        return None

model = load_model()

# ---------------------------
# 4. Sidebar & Input Mode
# ---------------------------
with st.sidebar:
    st.header("⚙️ Konfigurasi")
    st.markdown("Pilih metode input:")
    # URUTAN: Batch CSV Upload default
    input_mode = st.radio("Mode Input", ["Batch CSV Upload", "Single Simulation"])
    
    st.markdown("---")
    st.markdown("**Status Sistem**")
    if model:
        st.success("Model: Online (XGBoost)")
    else:
        st.error("Model: Offline (File tidak ditemukan)")
        st.info("Pastikan 'ids_model_final.pkl' ada di folder yang sama.")

# ---------------------------
# 5. Main Logic
# ---------------------------
st.title("🛡️ IDS Mitigation & SOC Playbook")
st.markdown("### Intelligent Intrusion Detection System")

# BLOK LOGIKA: Batch CSV Upload
if input_mode == "Batch CSV Upload":
    st.subheader("📂 Analisis Trafik Massal")
    
    # --- AREA DOWNLOAD (Template & Dummy) ---
    col_d1, col_d2 = st.columns(2)
    
    with col_d1:
        st.info("📄 **Format Data**")
        st.caption("Unduh template jika ingin mengisi data manual.")
        csv_template = generate_csv_template()
        st.download_button(
            label="📥 Download Template (.csv)",
            data=csv_template,
            file_name="network_traffic_template.csv",
            mime="text/csv",
        )
        
    with col_d2:
        st.success("🎲 **Data Testing Otomatis**")
        st.caption("Unduh data dummy acak (50 baris) untuk simulasi.")
        dummy_data = generate_dummy_csv(50)
        st.download_button(
            label="📥 Download Dummy Data (.csv)",
            data=dummy_data,
            file_name="dummy_traffic_test.csv",
            mime="text/csv",
        )
    
    st.markdown("---")
    # -------------------------------------

    uploaded_file = st.file_uploader("Upload Network Log (CSV atau Excel)", type=["csv", "xlsx"])
    
    if uploaded_file and model:
        try:
            # Deteksi tipe file dan handle error Excel
            if uploaded_file.name.endswith('.csv'):
                df = pd.read_csv(uploaded_file)
            else:
                try:
                    df = pd.read_excel(uploaded_file)
                except ImportError:
                    st.error("❌ Library 'openpyxl' tidak ditemukan. Harap upload file .CSV saja.")
                    st.stop()
                except Exception as e:
                    st.error(f"❌ Gagal membaca file Excel: {e}")
                    st.stop()
            
            # Validasi Kolom
            missing_cols = [col for col in SELECTED_FEATURES if col not in df.columns]
            if missing_cols:
                st.error(f"❌ File tidak valid. Kolom berikut hilang: {missing_cols}")
            else:
                # Predict
                X = df[SELECTED_FEATURES]
                predictions = model.predict(X)
                df['Predicted_Attack'] = predictions
                
                # Generate Actions for each row
                actions = []
                scripts = []
                for pred in predictions:
                    pb, _ = get_mitigation_plan(str(pred))
                    actions.append(pb['action'])
                    scripts.append(pb['script'])
                
                df['Mitigation_Action'] = actions
                df['Executed_Script'] = scripts
                
                st.write("### Hasil Analisis")
                st.dataframe(df)
                
                # Filter only attacks
                attacks_only = df[df['Predicted_Attack'] != "Benign"]
                if not attacks_only.empty:
                    st.error(f"⚠️ {len(attacks_only)} Ancaman Terdeteksi!")
                    st.dataframe(attacks_only[['Predicted_Attack', 'Mitigation_Action', 'Executed_Script']])
                else:
                    st.success("✅ Tidak ada ancaman terdeteksi dalam batch ini.")
                    
        except Exception as e:
            st.error(f"Terjadi kesalahan: {e}")

elif input_mode == "Single Simulation":
    st.subheader("🛠️ Simulasi Trafik Manual")
    
    inputs = {}
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("#### Info Dasar")
        inputs['Dst Port'] = st.number_input("Dst Port", min_value=0, value=80)
        inputs['Protocol'] = st.number_input("Protocol", min_value=0, value=6)
        inputs['Flow Duration'] = st.number_input("Flow Duration", value=1000)
        inputs['Tot Fwd Pkts'] = st.number_input("Tot Fwd Pkts", value=10)
        inputs['Tot Bwd Pkts'] = st.number_input("Tot Bwd Pkts", value=8)

    with col2:
        st.markdown("#### Statistik Paket")
        inputs['Fwd Pkt Len Mean'] = st.number_input("Fwd Pkt Len Mean", value=50.0)
        inputs['Bwd Pkt Len Mean'] = st.number_input("Bwd Pkt Len Mean", value=60.0)
        inputs['Flow Byts/s'] = st.number_input("Flow Byts/s", value=1000.0)
        inputs['Flow Pkts/s'] = st.number_input("Flow Pkts/s", value=20.0)
        
    with col3:
        st.markdown("#### Flags & Waktu")
        inputs['FIN Flag Cnt'] = st.number_input("FIN Flag Cnt", value=0)
        inputs['SYN Flag Cnt'] = st.number_input("SYN Flag Cnt", value=1)
        inputs['RST Flag Cnt'] = st.number_input("RST Flag Cnt", value=0)
        inputs['PSH Flag Cnt'] = st.number_input("PSH Flag Cnt", value=0)
        inputs['ACK Flag Cnt'] = st.number_input("ACK Flag Cnt", value=1)
    
    st.markdown("#### Advanced Timing (IAT)")
    c1, c2, c3 = st.columns(3)
    inputs['Flow IAT Mean'] = c1.number_input("Flow IAT Mean", value=50.0)
    inputs['Flow IAT Std'] = c2.number_input("Flow IAT Std", value=10.0)
    inputs['Flow IAT Max'] = c3.number_input("Flow IAT Max", value=100.0)

    # Optional: Mock IP for the report
    suspect_ip = st.text_input("Simulasi Source IP (Untuk Laporan)", "192.168.1.105")

    if st.button("🔍 Analisis Trafik"):
        if model:
            # Prepare Data
            input_df = pd.DataFrame([inputs], columns=SELECTED_FEATURES)
            
            # Prediction
            try:
                prediction = model.predict(input_df)[0]
                
                # Confidence score logic
                try:
                    probs = model.predict_proba(input_df)
                    confidence = np.max(probs) * 100
                except:
                    confidence = 100.0

                # Get Playbook
                playbook, timestamp = get_mitigation_plan(str(prediction), suspect_ip)
                
                # --- DISPLAY RESULTS ---
                st.divider()
                
                # Header
                r1, r2 = st.columns([1, 3])
                with r1:
                    if playbook['severity'] == "Safe":
                        st.image("https://upload.wikimedia.org/wikipedia/commons/thumb/3/3b/Oea_green_shield.svg/100px-Oea_green_shield.svg.png", width=80)
                    else:
                        st.image("https://upload.wikimedia.org/wikipedia/commons/thumb/d/dd/Achtung.svg/100px-Achtung.svg.png", width=80)
                
                with r2:
                    st.subheader(f"Hasil Deteksi: **{prediction}**")
                    st.caption(f"Confidence: {confidence:.2f}% | Waktu: {timestamp}")

                # SOC Playbook Card
                if playbook['severity'] != "Safe":
                    st.error(f"🚨 **ANCAMAN TERDETEKSI: {playbook['alert']}**")
                    
                    st.markdown("### 📋 SOC Playbook (Respon Otomatis)")
                    
                    col_a, col_b, col_c = st.columns(3)
                    col_a.metric("Severity", playbook['severity'])
                    col_a.metric("Aksi Utama", playbook['action'])
                    col_b.metric("Script Trigger", playbook['script'])
                    
                    st.markdown("**Rekomendasi Perintah (Command):**")
                    st.code(playbook['command'], language="bash")
                    
                    st.warning("⚠️ Catatan: Aksi ini telah dicatat ke database SOC.")
                else:
                    st.success("✅ **Trafik Normal (Benign).** Tidak ada mitigasi yang diperlukan.")
            except Exception as e:
                st.error(f"Gagal melakukan prediksi: {e}")