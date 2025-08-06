Python Packet Sniffer (Tkinter GUI)
A simple packet sniffer with a friendly graphical interface built using Tkinter and Scapy. This tool allows you to monitor IP packets live, view their source and destination addresses, and see real-time protocol statistics per session—all without leaving the GUI.

Features
Realtime IP packet sniffing using Scapy

User-friendly graphical interface with Tkinter

See source/destination addresses and protocol type (TCP, UDP, ICMP, or Other)

Live packet count per protocol and total captured

Start/stop controls

Final summary report after capture

Screenshot
Here’s how the program looks in action:

![Packet Sniffer Screenshot

Python 3.x

Scapy

Tkinter (usually included with Python)

Installation
bash
git clone https://github.com/yourusername/packet-sniffer-tk.git
cd packet-sniffer-tk
pip install scapy
(Tkinter is included with most Python installs.)

Usage
bash
python packet_sniffer_gui.py
Click "Start Sniffing" to begin and "Stop Sniffing" to end capture.

After stopping, a protocol-wise summary appears.

Note: Some systems may require administrator/root privileges:

bash
sudo python packet_sniffer_gui.py
About
Only IPv4 traffic is shown.

Use for educational/network diagnostic purposes.

Do not use on unauthorized networks.

License
MIT License

You can further customize this if you add more screenshots or info. Once you push this README along with your program and the screenshot, visitors to your GitHub repo will see the image displayed as shown above!.
