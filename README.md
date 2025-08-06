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

*(Add your screenshot below - e.g., rename it to `screenshot.png` and place it in your repo)*

![Packet Sniffer GUI](screenshot.png)

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
