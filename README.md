# 🐍 Basic Network Sniffer 

A simple yet powerful packet sniffer with a friendly graphical interface built using **Tkinter** and **Scapy**.  
This tool allows you to monitor live **IPv4 traffic**, view **source/destination IP addresses**, and see **real-time protocol statistics** — all within a streamlined GUI.

---

## 🚀 Features

- 🔄 Real-time IP packet sniffing powered by **Scapy**
- 🎛️ Interactive GUI built with **Tkinter**
- 🌐 Displays source/destination IPs and protocols (**TCP, UDP, ICMP, Others**)
- 📊 Live statistics: packet counts per protocol and total captured
- 🟢 **Start** and 🔴 **Stop** sniffing with buttons
- 🧾 Summary report shown after stopping the capture

---

## 🖼️ Screenshot


![image alt](https://github.com/y1v1n1/CodeAlpha_BasicNetworkSniffer/blob/a026e1c69b80261235d7b89ba8bfa42d48cd3653/Screenshot%202025-08-06%20191113.png)

---

## 📦 Requirements

- Python 3.x  
- Scapy → `pip install scapy`  
- Tkinter (usually included with Python by default)

---

## 🔧 Installation

```bash
git clone https://github.com/yourusername/packet-sniffer-tk.git
cd packet-sniffer-tk
pip install scapy
```
---


##▶️ Usage
```bash
python packet_sniffer_gui.py
```
•	Click “Start Sniffing” to begin monitoring.
•	Click “Stop Sniffing” to halt the capture and view the summary.
🔐 Note: Administrator/root access may be required:

```bash
sudo python packet_sniffer_gui.py
```


