from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP

class AccessControlList:
    def __init__(self):
        self.rule_list = []

    def add_rule(self, rule):
        self.rule_list.append(rule)

    def remove_rule(self, rule):
        self.rule_list.remove(rule)

    def remove_all_rules(self):
        self.rule_list = []

    def check_packet(self, frame, interface, direction, rule):
        checks = []

        if rule.interface != interface or direction != rule.direction:
            return False

        if rule.src_mac != 'any' and frame[Ether].src.lower() != rule.src_mac:
            checks.append(False)

        if rule.dst_mac != 'any' and frame[Ether].dst.lower() != rule.dst_mac:
            checks.append(False)

        if IP in frame:
            frame_ip = frame[IP]
            if rule.src_ip != 'any' and frame_ip.src != rule.src_ip:
                checks.append(False)

            if rule.dst_ip != 'any' and frame_ip.dst != rule.dst_ip:
                checks.append(False)

            if TCP in frame:
                frame_tcp = frame[TCP]
                if rule.src_port != 'any' and frame_tcp.sport != int(rule.src_port):
                    checks.append(False)

                if rule.dst_port != 'any' and frame_tcp.dport != int(rule.dst_port):
                    checks.append(False)

            elif UDP in frame:
                frame_udp = frame[UDP]
                if rule.src_port != 'any' and frame_udp.sport != int(rule.src_port):
                    checks.append(False)

                if rule.dst_port != 'any' and frame_udp.dport != int(rule.dst_port):
                    checks.append(False)

            elif ICMP in frame:
                frame_icmp = frame[ICMP]
                if rule.icmp_type == 'none':
                    checks.append(False)
                elif rule.icmp_type != 'any' and frame_icmp.type != int(rule.icmp_type):
                    checks.append(False)

        return False if False in checks else True

    def check_rule(self, frame, interface, direction):
        if not self.rule_list or ARP in frame:
            return True
        else:
            for rule in self.rule_list:
                if self.check_packet(frame, interface, direction, rule):
                    if rule.action == 'Permit':
                        return True

                    elif rule.action == 'Deny':
                        return False

            return True

    def set_rule_priority(self, row_rule):
        self.rule_list.sort(key=lambda r: self.get_row_by_rule(r, row_rule))
        increment = 0
        for rule in self.rule_list:
            rule.priority = increment
            increment += 1

    def get_row_by_rule(self, rule, row_rule):
        for row, r in row_rule.items():
            if r == rule:
                return row
