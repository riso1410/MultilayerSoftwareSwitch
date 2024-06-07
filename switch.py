import psutil

from port import Port
import threading
from collections import deque
from scapy.layers.l2 import Ether, ARP
from mac_table import MacTable
from PyQt5.QtCore import QObject
import time


class Switch(QObject):
    def __init__(self, stats_manager, acl, syslog):
        super().__init__()
        self.clear_timer = time.time()
        self.stats_manager = stats_manager
        self.port1 = None
        self.port2 = None
        self.ports = []
        self.mac_table_obj = MacTable()
        self.received_frames = deque(maxlen=10)
        self.acl_obj = acl
        self.syslog_obj = syslog
        self.interface_down_times = {}
        self.interface_status_thread = threading.Thread(target=self.interface_status, daemon=True)

    # Method to start the switch, creates two ports and starts them
    def start(self, interface_1, interface_2):
        # Controls two ports running on threads simultaneously
        self.port1 = Port(interface_1, self.receive_frame, self.forward_frame, self.acl_obj)
        self.port2 = Port(interface_2, self.receive_frame, self.forward_frame, self.acl_obj)

        self.ports.append(self.port1)
        self.ports.append(self.port2)

        port1_thread = threading.Thread(target=self.port1.receive, daemon=True)
        port2_thread = threading.Thread(target=self.port2.receive, daemon=True)

        port1_thread.start()
        port2_thread.start()
        self.interface_status_thread.start()

    # Method to receive a frame from a port
    def receive_frame(self, frame, receive_port):
        src_mac = frame[Ether].src
        dst_mac = frame[Ether].dst

        # Remove switch MACs, reduction MACs, keep only PC MACs
        if dst_mac.startswith('f8:e') or src_mac.startswith('f8:e') or \
                dst_mac.startswith('00:e') or src_mac.startswith('00:e') or \
                dst_mac.startswith('e4:a') or src_mac.startswith('e4:a') or \
                dst_mac.startswith('14:4') or src_mac.startswith('14:4'):
            return

        hash_frame = frame.show(dump=True)

        if hash_frame in self.received_frames:
            if time.time() - self.clear_timer >= 5:
                self.received_frames.clear()
                if self.syslog_obj:
                    self.syslog_obj.send_message(f'Hashtable of received frames cleared', 'DEBUG')
            else:
                return
        else:
            self.clear_timer = time.time()
            self.received_frames.append(hash_frame)

        # Port 1 INPUT stats
        if receive_port.interface == self.port1.interface:
            self.stats_manager.in_stats('port1_stats', frame)

        # Port 2 INPUT stats
        elif receive_port.interface == self.port2.interface:
            self.stats_manager.in_stats('port2_stats', frame)

        # MAC table learning
        if src_mac not in self.mac_table_obj.mac_table:
            self.mac_table_obj.add_entry(src_mac, receive_port.interface)

        # Update entry
        elif src_mac in self.mac_table_obj.mac_table:
            if self.mac_table_obj.mac_table[src_mac]["port"] != receive_port.interface:
                self.mac_table_obj.mac_table[src_mac]["port"] = receive_port.interface
                if self.syslog_obj:
                    self.syslog_obj.send_message(f'New port set {self.mac_table_obj.mac_table[src_mac]["port"]} ->\
                     {receive_port.interface}', 'NOTICE')

            self.mac_table_obj.refresh_timer(src_mac)

        # MAC table forwarding
        # Unicast
        if dst_mac in self.mac_table_obj.mac_table:
            forward_port = next(
                (port for port in self.ports if port.interface == self.mac_table_obj.mac_table[dst_mac]["port"]), None)
            if forward_port != receive_port:
                forward_port.forward(frame)

        # Broadcast
        elif dst_mac not in self.mac_table_obj.mac_table:
            for port in self.ports:
                if port != receive_port:
                    port.forward(frame)

    # Method to forward a frame to the other port
    def forward_frame(self, frame, interface_id):
        # Port 1 OUTPUT stats
        if interface_id == self.port1.interface:
            self.stats_manager.out_stats('port1_stats', frame)

        # Port 2 OUTPUT stats
        elif interface_id == self.port2.interface:
            self.stats_manager.out_stats('port2_stats', frame)

    # Method for checking if cable is unplugged and then remove entries from mac table of same interface
    def interface_status(self):
        while True:
            for port in self.ports:
                if not psutil.net_if_stats()[port.interface].isup:
                    self.received_frames.clear()
                    if self.syslog_obj:
                        self.syslog_obj.send_message(f'Hashtable of received frames cleared', 'DEBUG')
                    if port.interface not in self.interface_down_times:
                        self.interface_down_times[port.interface] = time.time()
                    elif time.time() - self.interface_down_times[port.interface] >= 10:
                        self.mac_table_obj.remove_entry_interface(port.interface)
                        if self.syslog_obj:
                            self.syslog_obj.send_message(f'Cable was unplugged for over 10s on interface {port.interface}', 'WARNING')
                else:
                    if port.interface in self.interface_down_times:
                        del self.interface_down_times[port.interface]
            time.sleep(1)
