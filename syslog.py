import socket
import struct
import datetime
from scapy.all import IP, UDP, send


class Syslog:
    def __init__(self, src_ip, dest_ip, switch, dest_port=514):
        self.switch = switch
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.dest_port = dest_port

    # Method to send and form a message to the syslog server
    def send_message(self, message, severity):
        formatted_message = f'<{str(severity)}>{str(datetime.datetime.now())} {self.src_ip}: {message}'
        packet = IP(src=self.src_ip, dst=self.dest_ip)/UDP(sport=42069, dport=self.dest_port)/formatted_message
        try:
            send(packet, iface=self.switch.port1.interface, verbose=False)
        except:
            send(packet, iface=self.switch.port2.interface, verbose=False)
