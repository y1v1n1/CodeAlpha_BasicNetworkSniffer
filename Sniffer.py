import tkinter as tk
from scapy.all import sniff, IP
from threading import Thread
from datetime import datetime

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Python Packet Sniffer")
        self.running = False
        self.packet_count = 0

        # Count per protocol
        self.protocol_counts = {
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0,
            "Other": 0
        }

        # Text area for displaying packets
        self.text = tk.Text(root, height=25, width=110)
        self.text.pack()

        # Buttons
        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=10)

        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing)
        self.stop_button.pack(side=tk.LEFT)

    def log(self, message):
        self.text.insert(tk.END, message + "\n")
        self.text.see(tk.END)

    def get_protocol_info(self, proto_num):
        if proto_num == 6:
            return "TCP", "Transmission Control Protocol (used in HTTP, FTP, etc.)"
        elif proto_num == 17:
            return "UDP", "User Datagram Protocol (used in DNS, video streaming, etc.)"
        elif proto_num == 1:
            return "ICMP", "Internet Control Message Protocol (used for ping)"
        else:
            return "Other", "Unknown or uncommon protocol"

    def show_packet(self, packet):
        if not self.running:
            return
        if IP in packet:
            ip_layer = packet[IP]
            time = datetime.now().strftime("%H:%M:%S")
            proto_name, proto_desc = self.get_protocol_info(ip_layer.proto)
            self.packet_count += 1
            self.protocol_counts[proto_name] += 1
            log_msg = (
                f"[{time}] Packet #{self.packet_count}\n"
                f"   From: {ip_layer.src} --> To: {ip_layer.dst}\n"
                f"   Protocol: {proto_name} ({proto_desc})\n"
            )
            self.log(log_msg)

    def sniff_packets(self):
        sniff(prn=self.show_packet, store=False, filter="ip", stop_filter=lambda x: not self.running)

    def start_sniffing(self):
        if not self.running:
            self.running = True
            self.packet_count = 0
            self.protocol_counts = {k: 0 for k in self.protocol_counts}
            self.thread = Thread(target=self.sniff_packets)
            self.thread.start()
            self.log("🚀 Sniffing started...\n")

    def stop_sniffing(self):
        if self.running:
            self.running = False
            self.log("🛑 Sniffing stopped.")
            self.log(f"\n📊 Summary Report:")
            self.log(f"   📦 Total packets: {self.packet_count}")
            for proto, count in self.protocol_counts.items():
                self.log(f"   {proto}: {count} packets")

# Run the app
if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
