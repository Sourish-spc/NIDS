# live_capture.py

# Import necessary libraries
import pandas as pd
import numpy as np
import joblib
import warnings
import time

# Suppress scapy IPv6 warning
warnings.filterwarnings("ignore", category=UserWarning, module="scapy")

try:
    from scapy.all import sniff, send, IP, TCP, UDP
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

import pandas as pd
from scapy.all import sniff

# Assume you already trained your `model` on UNSW-NB15 features

def extract_features(packet):
    try:
        proto = packet.proto if hasattr(packet, 'proto') else 0
        length = len(packet)
        src_port = packet.sport if hasattr(packet, 'sport') else 0
        dst_port = packet.dport if hasattr(packet, 'dport') else 0

        # Create dict of extracted values
        return {
            "proto": proto,
            "sport": src_port,
            "dsport": dst_port,
            "pkt_size": length
        }
    except Exception as e:
        print(f"Feature extraction error: {e}")
        return None

def process_packet(packet):
    features = extract_features(packet)
    if features is not None:
        # Wrap into DataFrame so it's compatible with the model
        df = pd.DataFrame([features])

        # Prediction
        prediction = model.predict(df)[0]
        print("Prediction:", "🚨 Attack" if prediction == 1 else "✅ Normal")

print("Starting live network capture... Press Ctrl+C to stop.")
sniff(prn=process_packet, store=0)

# --- 3. Simulate an Attack (Optional) ---
def simulate_syn_flood(target_ip, target_port=80, count=50):
    """Sends a burst of TCP SYN packets to simulate a SYN flood attack."""
    print(f"\n--- Simulating a SYN Flood Attack ---")
    print(f"Sending {count} TCP SYN packets to {target_ip}:{target_port}")
    # Craft the malicious packet
    packet = IP(dst=target_ip) / TCP(sport=12345, dport=target_port, flags="S")
    # Send the packets in a burst
    send(packet, count=count, verbose=0)
    print("--- Simulation Complete ---\n")

# --- 4. Packet Processing and Prediction ---

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
                # Highlight detected attacks
                if result == "Attack":
                    print(f"\033[91mATTACK DETECTED: {packet[IP].src}:{src_port} -> {packet[IP].dst}:{dst_port} | Confidence: {confidence:.2f}%\033[0m")
                else:
                    print(f"Packet: {packet[IP].src}:{src_port} -> {packet[IP].dst}:{dst_port} | Prediction: {result} (Confidence: {confidence:.2f}%)")
        except Exception as e:
            print(f"Error predicting packet: {e}")

# --- 5. Start Live Capture ---
# Ask the user if they want to simulate an attack first
test_choice = input("Do you want to send fake intrusion packets to test the system? (yes/no): ").lower()
if test_choice in ['yes', 'y']:
    target_ip = input("Enter the target IP address (e.g., 127.0.0.1 or 192.168.1.10): ")
    print("\n\033[93mWARNING: Ensure you have permission to send packets to this IP address.\033[0m")
    print("\033[93mSending unsolicited packets can be disruptive and is not recommended on networks you don't own.\033[0m\n")
    confirm_send = input(f"Are you sure you want to send packets to {target_ip}? (yes/no): ").lower()
    
    if confirm_send in ['yes', 'y']:
        simulate_syn_flood(target_ip=target_ip)
        print("Waiting 2 seconds before starting live capture...")
        time.sleep(2)
    else:
        print("Attack simulation cancelled.")


print("\nStarting live network capture... Press Ctrl+C to stop.")
try:
    # Start sniffing. You might need to run this with sudo/administrator privileges.
    sniff(prn=packet_callback, store=0)
except PermissionError:
    print("\nPERMISSION ERROR: Please run this script with administrator/root privileges.")
except Exception as e:
    print(f"\nAn error occurred during packet sniffing: {e}")
