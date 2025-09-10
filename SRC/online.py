# live_capture.py

# Import necessary libraries
import pandas as pd
import numpy as np
import joblib
import warnings

# Suppress scapy IPv6 warning
warnings.filterwarnings("ignore", category=UserWarning, module="scapy")

try:
    from scapy.all import sniff, IP, TCP, UDP
except ImportError:
    print("\nERROR: Scapy is not installed. Please install it using 'pip install scapy'")
    exit()

# --- 1. Load the Trained Model ---
print("Loading the trained model...")
try:
    model_data = joblib.load('nids_model.joblib')
    model = model_data['model']
    model_columns = model_data['columns']
except FileNotFoundError:
    print("\nERROR: Model file 'nids_model.joblib' not found.")
    print("Please run the 'train_model.py' script first to train and save the model.")
    exit()
print("Model loaded successfully.")


# --- 2. Helper Functions for Feature Extraction ---

def get_service(port):
    """Maps a port number to a service name."""
    service_map = {
        80: 'http', 21: 'ftp', 22: 'ssh', 23: 'telnet',
        25: 'smtp', 53: 'dns', 443: 'https',
    }
    return service_map.get(port, '-')

def get_protocol_name(proto_num):
    """Maps a protocol number to its name."""
    protocol_map = {1: 'icmp', 6: 'tcp', 17: 'udp'}
    return protocol_map.get(proto_num, 'unknown')

def extract_features(packet):
    """
    Extracts features from a live packet to match the model's input format.
    NOTE: This is a simplified, single-packet approach. Many dataset features
    are flow-based and are approximated here with default values.
    """
    features = {col: 0 for col in model_columns}

    if IP in packet:
        # Basic packet info
        features['proto'] = get_protocol_name(packet[IP].proto)
        features['sbytes'] = packet[IP].len
        features['spkts'] = 1
        features['sttl'] = packet[IP].ttl

        # Default values for flow-based features
        features['dur'], features['rate'], features['dbytes'], features['dpkts'] = 0, 0, 0, 0
        features['ct_srv_src'], features['ct_dst_ltm'], features['ct_src_dport_ltm'] = 1, 1, 1
        features['ct_dst_sport_ltm'], features['ct_dst_src_ltm'], features['ct_src_ltm'] = 1, 1, 1
        features['ct_srv_dst'] = 1

        if TCP in packet:
            features['service'] = get_service(packet[TCP].dport)
            flags = packet[TCP].flags
            if 'F' in flags: features['state'] = 'FIN'
            elif 'S' in flags: features['state'] = 'SYN'
            elif 'R' in flags: features['state'] = 'RST'
            else: features['state'] = 'CON'
        elif UDP in packet:
            features['service'] = get_service(packet[UDP].dport)
            features['state'] = 'CON'
        else:
            features['service'] = '-'
            features['state'] = 'INT'

    # Convert to a DataFrame with the correct column order
    return pd.DataFrame([features], columns=model_columns)


# --- 3. Packet Processing and Prediction ---

def packet_callback(packet):
    """Callback function to process and classify each captured packet."""
    feature_df = extract_features(packet)

    if not feature_df.empty:
        try:
            # Use the loaded model to predict
            prediction = model.predict(feature_df)
            prediction_proba = model.predict_proba(feature_df)

            result = "🚨Attack" if prediction[0] == 1 else "✅Normal"
            confidence = prediction_proba[0][prediction[0]] * 100

            # Print the result
            if IP in packet:
                src_port = packet.sport if TCP in packet or UDP in packet else ''
                dst_port = packet.dport if TCP in packet or UDP in packet else ''
                print(f"Packet: {packet[IP].src}:{src_port} -> {packet[IP].dst}:{dst_port} | Prediction: {result} (Confidence: {confidence:.2f}%)")
        except Exception as e:
            print(f"Error predicting packet: {e}")


# --- 4. Start Live Capture ---
print("\nStarting live network capture... Press Ctrl+C to stop.")
try:
    # Start sniffing. You might need to run this with sudo/administrator privileges.
    sniff(prn=packet_callback, store=0)
except PermissionError:
    print("\nPERMISSION ERROR: Please run this script with administrator/root privileges.")
except Exception as e:
    print(f"\nAn error occurred during packet sniffing: {e}")

