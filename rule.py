class Rule:
    def __init__(self):
        self.priority = None  # Row Number
        self.interface = None
        self.direction = None
        self.action = None
        self.src_mac = None
        self.dst_mac = None
        self.src_ip = None
        self.dst_ip = None
        self.src_port = None
        self.dst_port = None
        self.icmp_type = None

    def set_rules(self, priority, interface, direction, action, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port,
                  icmp_type):
        self.priority = priority
        self.interface = interface
        self.direction = direction
        self.action = action
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.icmp_type = icmp_type
