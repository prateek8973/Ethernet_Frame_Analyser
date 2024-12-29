import React, { useState } from 'react';
import axios from 'axios';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, LineChart, Line } from 'recharts';
import './App.css';

function App() {
    const [file, setFile] = useState(null);
    const [result, setResult] = useState(null);
    const [loading, setLoading] = useState(false);

    const handleFileChange = (e) => {
        setFile(e.target.files[0]);
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        const formData = new FormData();
        formData.append('file', file);
        setLoading(true);

        try {
            const response = await axios.post('http://localhost:5000/upload', formData, {
                headers: {
                    'Content-Type': 'multipart/form-data'
                }
            });
            setResult(response.data.data);
        } catch (error) {
            console.error('Error uploading file:', error);
        } finally {
            setLoading(false);
        }
    };

    const kmeansData = result ? result.kmeans_labels.map((label, index) => ({ name: `Packet ${index + 1}`, label })) : [];
    const anomaliesData = result ? result.anomalies.map((anomaly, index) => ({ name: `Packet ${index + 1}`, anomaly })) : [];
    const ethernetHeaders = result ? result.ethernet_headers : [];
    const summary = result ? result.summary : null;

    const etherTypeMap = {
        0x0800: 'IPv4',
        0x86DD: 'IPv6',
        0x0806: 'ARP',
        // Add more EtherTypes as needed
    };

    return (
        <div className="container">
            <header>
                <h1>Ethernet Frame Analysis and Anomaly Detection</h1>
                <p>Upload a PACP file to analyze Ethernet frames and detect anomalies using K-means clustering and Autoencoders.</p>
            </header>
            <main>
                <section className="summary">
                    <h2>Project Summary</h2>
                    <p>This project aims to analyze Ethernet frames captured in PACP files. By leveraging machine learning techniques such as K-means clustering and Autoencoders, we can detect anomalies in the network traffic. The backend is built using Python Flask, and the frontend is developed with React. The results of the analysis are visualized using Recharts.</p>
                </section>
                {summary && (
                    <section className="packet-summary">
                        <h2>Packet Summary</h2>
                        <p><strong>Total Packets:</strong> {summary.total_packets}</p>
                        <p><strong>Protocol Counts:</strong></p>
                        <ul>
                            <li><strong>IPv4:</strong> {summary.protocol_counts.IPv4}</li>
                            <li><strong>IPv6:</strong> {summary.protocol_counts.IPv6}</li>
                            <li><strong>ARP:</strong> {summary.protocol_counts.ARP}</li>
                            <li><strong>TCP:</strong> {summary.protocol_counts.TCP}</li>
                            <li><strong>UDP:</strong> {summary.protocol_counts.UDP}</li>
                        </ul>
                    </section>
                )}
                <section className="ml-techniques">
                    <h2>Machine Learning Techniques Used</h2>
                    <p><strong>K-means Clustering:</strong> K-means clustering is an unsupervised learning algorithm that groups data into clusters based on their features. In this project, it is used to group Ethernet frames with similar characteristics.</p>
                    <p><strong>Autoencoders:</strong> Autoencoders are a type of neural network used for anomaly detection. They learn to compress and reconstruct data, and anomalies are detected based on the reconstruction error.</p>
                </section>
                <section className="packet-analysis">
                    <h2>Packet Analysis</h2>
                    <p>The analysis involves extracting features from the Ethernet frames, such as packet length and timestamp. These features are then used as input for the machine learning models to detect patterns and anomalies in the network traffic.</p>
                </section>
                <section className="ethernet-header">
                    <h2>Ethernet Header Details</h2>
                    <p>The Ethernet header is a critical part of the Ethernet frame, containing essential information for the delivery of packets. Here are the main components of the Ethernet header:</p>
                    <ul>
                        <li><strong>Destination MAC Address:</strong> The MAC address of the destination device.</li>
                        <li><strong>Source MAC Address:</strong> The MAC address of the source device.</li>
                        <li><strong>EtherType:</strong> Indicates the protocol encapsulated in the payload of the frame (e.g., IPv4, IPv6).</li>
                    </ul>
                    <p>Understanding these components is crucial for analyzing network traffic and identifying anomalies.</p>
                    {ethernetHeaders.length > 0 && (
                        <table>
                            <thead>
                                <tr>
                                    <th>Packet</th>
                                    <th>Length</th>
                                    <th>Timestamp</th>
                                    <th>Source MAC</th>
                                    <th>Destination MAC</th>
                                    <th>EtherType</th>
                                    <th>Source IP</th>
                                    <th>Destination IP</th>
                                    <th>Protocol</th>
                                    <th>Source Port</th>
                                    <th>Destination Port</th>
                                </tr>
                            </thead>
                            <tbody>
                                {ethernetHeaders.map((header, index) => (
                                    <tr key={index}>
                                        <td>{`Packet ${index + 1}`}</td>
                                        <td>{header[0]}</td>
                                        <td>{new Date(header[1] * 1000).toLocaleString()}</td>
                                        <td>{header[2]}</td>
                                        <td>{header[3]}</td>
                                        <td>{etherTypeMap[header[4]] || header[4]}</td>
                                        <td>{header[5]}</td>
                                        <td>{header[6]}</td>
                                        <td>{header[7]}</td>
                                        <td>{header[8]}</td>
                                        <td>{header[9]}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    )}
                </section>
                <form onSubmit={handleSubmit} className="upload-form">
                    <input type="file" onChange={handleFileChange} className="file-input" />
                    <button type="submit" className="upload-button">Upload</button>
                </form>
                {loading && <p>Loading...</p>}
                {result && (
                    <div className="charts">
                        <h2>K-means Clustering</h2>
                        <p>The K-means clustering graph shows how the Ethernet frames are grouped into clusters based on their features. Each bar represents a packet and its corresponding cluster label. The height of the bar indicates the cluster label assigned to that packet.</p>
                        <BarChart
                            width={600}
                            height={300}
                            data={kmeansData}
                            margin={{
                                top: 5, right: 30, left: 20, bottom: 5,
                            }}
                        >
                            <CartesianGrid strokeDasharray="3 3" />
                            <XAxis dataKey="name" />
                            <YAxis />
                            <Tooltip />
                            <Legend />
                            <Bar dataKey="label" fill="#8884d8" />
                        </BarChart>
                        <h2>Anomalies</h2>
                        <p>The anomalies graph shows the packets that are considered anomalies based on the reconstruction error from the autoencoder. Each point represents a packet, and the y-axis indicates whether the packet is an anomaly.</p>
                        <LineChart
                            width={600}
                            height={300}
                            data={anomaliesData}
                            margin={{
                                top: 5, right: 30, left: 20, bottom: 5,
                            }}
                        >
                            <CartesianGrid strokeDasharray="3 3" />
                            <XAxis dataKey="name" />
                            <YAxis />
                            <Tooltip />
                            <Legend />
                            <Line type="monotone" dataKey="anomaly" stroke="#8884d8" />
                        </LineChart>
                    </div>
                )}
            </main>
        </div>
    );
}

export default App;