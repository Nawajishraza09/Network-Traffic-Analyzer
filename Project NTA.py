from scapy.all import sniff, IP, TCP, UDP
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.ensemble import IsolationForest
import numpy as np
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# List to store captured packet data
packets_data = []


# SMTP configuration
SMTP_SERVER = 'smtp.mail.com'  # Replace with your SMTP server
SMTP_PORT = 587  # Replace with your SMTP port
SMTP_USER = 'sender_mail@example.com'  # Replace with your email
SMTP_PASSWORD = 'your_email_password'  # Replace with your email/app password
ALERT_EMAIL = 'recipient_email@example.com'  # Replace with the recipient email

def send_alert(anomalies):
    subject = "Network Anomaly Detected"
    body = f"The following anomalies were detected in the network traffic:\n{anomalies.to_string()}"
    
    msg = MIMEMultipart()
    msg['From'] = SMTP_USER
    msg['To'] = ALERT_EMAIL
    msg['Subject'] = subject
    
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(SMTP_USER, ALERT_EMAIL, msg.as_string())
        server.quit()
        print("Alert email sent successfully")
    except Exception as e:
        print(f"Failed to send email: {e}")


# Packet sniffing
def packet_callback(packet):
    if IP in packet and TCP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        tcp_sport = packet[TCP].sport
        tcp_dport = packet[TCP].dport
        print(f"{ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport}")
        packets_data.append((ip_src, ip_dst, tcp_sport, tcp_dport))

        if IP in packet and UDP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            udp_sport = packet[UDP].sport
            udp_dport = packet[UDP].dport
            print(f"{ip_src}:{udp_sport} -> {ip_dst}:{udp_dport}")
            packets_data.append((ip_src, ip_dst, udp_sport, udp_dport))


# Function to detect anomalies
def analyze_traffic(packets_data):
    df = pd.DataFrame(packets_data, columns=['src_ip', 'dst_ip', 'src_port', 'dst_port'])
    df['count'] = df.groupby('src_ip')['src_ip'].transform('count')
    features = df[['count']].values
    
    clf = IsolationForest(contamination=0.1)
    clf.fit(features)
    df['anomaly'] = clf.predict(features)

    
# Visualizing the traffic data
    df.plot(kind='bar', x='src_ip', y='count')
    plt.show()
    
    anomalies = df[df['anomaly'] == -1]
    if not anomalies.empty:
        print("Anomalies detected:")
        print(anomalies)
        send_alert(anomalies)

sniff(prn=packet_callback, count=50)
analyze_traffic(packets_data)



