from PyQt5.QtCore import QObject, pyqtSignal
import threading
import time
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP


class StatisticsManager(QObject):
    stats_update = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.refresh_thread = threading.Thread(target=self.refresh_stats, daemon=True)
        self.refresh_thread.start()
        self.port1_stats = {
            "Ethernet II (IN)": 0,
            "ARP (IN)": 0,
            "IP (IN)": 0,
            "TCP (IN)": 0,
            "UDP (IN)": 0,
            "ICMP (IN)": 0,
            "HTTPS (IN)": 0,
            "Ethernet II (OUT)": 0,
            "ARP (OUT)": 0,
            "IP (OUT)": 0,
            "TCP (OUT)": 0,
            "UDP (OUT)": 0,
            "ICMP (OUT)": 0,
            "HTTPS (OUT)": 0,
        }

        self.port2_stats = {
            "Ethernet II (IN)": 0,
            "ARP (IN)": 0,
            "IP (IN)": 0,
            "TCP (IN)": 0,
            "UDP (IN)": 0,
            "ICMP (IN)": 0,
            "HTTPS (IN)": 0,
            "Ethernet II (OUT)": 0,
            "ARP (OUT)": 0,
            "IP (OUT)": 0,
            "TCP (OUT)": 0,
            "UDP (OUT)": 0,
            "ICMP (OUT)": 0,
            "HTTPS (OUT)": 0,
        }

    def clear_statistics(self, key):
        if key == "port1":
            for key in self.port1_stats.keys():
                self.port1_stats[key] = 0
        elif key == "port2":
            for key in self.port2_stats.keys():
                self.port2_stats[key] = 0

    def refresh_stats(self):
        while True:
            self.stats_update.emit()
            time.sleep(1)

    def get_stats(self, port):
        if port == 'port1':
            return self.port1_stats
        elif port == 'port2':
            return self.port2_stats
        else:
            return None

    def in_stats(self, port, frame):
        if port == 'port1_stats':
            if Ether in frame:
                self.port1_stats['Ethernet II (IN)'] += 1
                if ARP in frame:
                    self.port1_stats['ARP (IN)'] += 1
                if IP in frame:
                    self.port1_stats['IP (IN)'] += 1
                    if ICMP in frame:
                        self.port1_stats['ICMP (IN)'] += 1
                    if TCP in frame:
                        self.port1_stats['TCP (IN)'] += 1
                        if frame[TCP].sport == 443:
                            self.port1_stats['HTTPS (IN)'] += 1
                    if UDP in frame:
                        self.port1_stats['UDP (IN)'] += 1

        elif port == 'port2_stats':
            if Ether in frame:
                self.port2_stats['Ethernet II (IN)'] += 1
                if ARP in frame:
                    self.port2_stats['ARP (IN)'] += 1
                if IP in frame:
                    self.port2_stats['IP (IN)'] += 1
                    if ICMP in frame:
                        self.port2_stats['ICMP (IN)'] += 1
                    if TCP in frame:
                        self.port2_stats['TCP (IN)'] += 1
                        if frame[TCP].sport == 443:
                            self.port2_stats['HTTPS (IN)'] += 1
                    if UDP in frame:
                        self.port2_stats['UDP (IN)'] += 1

    def out_stats(self, port, frame):
        if port == 'port1_stats':
            if Ether in frame:
                self.port1_stats['Ethernet II (OUT)'] += 1
                if ARP in frame:
                    self.port1_stats['ARP (OUT)'] += 1
                if IP in frame:
                    self.port1_stats['IP (OUT)'] += 1
                    if ICMP in frame:
                        self.port1_stats['ICMP (OUT)'] += 1
                    if TCP in frame:
                        self.port1_stats['TCP (OUT)'] += 1
                        if frame[TCP].dport == 443:
                            self.port1_stats['HTTPS (OUT)'] += 1
                    if UDP in frame:
                        self.port1_stats['UDP (OUT)'] += 1

        elif port == 'port2_stats':
            if Ether in frame:
                self.port2_stats['Ethernet II (OUT)'] += 1
                if ARP in frame:
                    self.port2_stats['ARP (OUT)'] += 1
                if IP in frame:
                    self.port2_stats['IP (OUT)'] += 1
                    if ICMP in frame:
                        self.port2_stats['ICMP (OUT)'] += 1
                    if TCP in frame:
                        self.port2_stats['TCP (OUT)'] += 1
                        if frame[TCP].dport == 443:
                            self.port2_stats['HTTPS (OUT)'] += 1
                    if UDP in frame:
                        self.port2_stats['UDP (OUT)'] += 1
