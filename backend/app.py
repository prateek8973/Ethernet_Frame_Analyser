from flask import Flask, request, jsonify
from scapy.all import rdpcap, Ether, IP, TCP, UDP, ARP
from sklearn.cluster import KMeans
from sklearn.neural_network import MLPRegressor
import numpy as np
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

def extract_features(packets):
    features = []
    summary = {
        "total_packets": len(packets),
        "protocol_counts": {"IPv4": 0, "IPv6": 0, "ARP": 0, "TCP": 0, "UDP": 0}
    }
    for packet in packets:
        if packet.haslayer(Ether):
            eth = packet.getlayer(Ether)
            ip = packet.getlayer(IP)
            tcp = packet.getlayer(TCP)
            udp = packet.getlayer(UDP)
            if ip:
                if ip.version == 4:
                    summary["protocol_counts"]["IPv4"] += 1
                elif ip.version == 6:
                    summary["protocol_counts"]["IPv6"] += 1
            if packet.haslayer(ARP):
                summary["protocol_counts"]["ARP"] += 1
            if tcp:
                summary["protocol_counts"]["TCP"] += 1
            if udp:
                summary["protocol_counts"]["UDP"] += 1
            features.append([
                len(packet),  # Packet length
                packet.time,  # Timestamp
                eth.src,      # Source MAC Address
                eth.dst,      # Destination MAC Address
                eth.type,     # EtherType
                ip.src if ip else None,  # Source IP Address
                ip.dst if ip else None,  # Destination IP Address
                ip.proto if ip else None,  # Protocol
                tcp.sport if tcp else (udp.sport if udp else None),  # Source Port
                tcp.dport if tcp else (udp.dport if udp else None)   # Destination Port
            ])
    return np.array(features, dtype=object), summary  # Use dtype=object to handle mixed data types

def kmeans_clustering(features):
    kmeans = KMeans(n_clusters=3)
    kmeans.fit(features[:, :2].astype(float))  # Ensure numerical features are float
    return kmeans.labels_

def build_autoencoder(input_dim):
    autoencoder = MLPRegressor(hidden_layer_sizes=(16, 8, 4, 8, 16), activation='relu', solver='adam', max_iter=200)
    return autoencoder

def autoencoder_anomaly_detection(features):
    autoencoder = build_autoencoder(features.shape[1])
    autoencoder.fit(features[:, :2].astype(float), features[:, :2].astype(float))  # Ensure numerical features are float
    reconstructions = autoencoder.predict(features[:, :2].astype(float))
    mse = np.mean(np.power(features[:, :2].astype(float) - reconstructions, 2), axis=1)
    threshold = np.percentile(mse, 95)
    anomalies = mse > threshold
    return anomalies

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    file.save('uploaded.pcap')
    packets = rdpcap('uploaded.pcap')

    features, summary = extract_features(packets)
    
    kmeans_labels = kmeans_clustering(features)
    anomalies = autoencoder_anomaly_detection(features)
    
    analysis_results = {
        "kmeans_labels": kmeans_labels.tolist(),
        "anomalies": anomalies.tolist(),
        "ethernet_headers": features.tolist(),  # Include Ethernet header details in the response
        "summary": summary
    }

    results = {"message": "Analysis complete", "data": analysis_results}
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True)