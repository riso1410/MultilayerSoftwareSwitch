from scapy.all import *


class Port:
    def __init__(self, interface, receive_frame, forward_frame, acl):
        super().__init__()
        self.acl = acl
        self.interface = interface
        self.receive_frame = receive_frame
        self.forward_frame = forward_frame

    # Thread method to receive frames and parse them 
    def receive(self):
        while True:
            try:
                sniff(iface=self.interface, prn=self.handle_frame)
            except:
                pass

    def handle_frame(self, frame):
        # ACL check close to the source
        if not self.acl.check_rule(frame, self.interface, "IN"):
            return
        self.receive_frame(frame, self)

    # Method to forward a frame to the interface of Port
    def forward(self, frame):
        while True:
            try:
                # ACL closest to destination
                if not self.acl.check_rule(frame, self.interface, "OUT"):
                    return
                sendp(frame, iface=self.interface)
                self.forward_frame(frame, self.interface)
                break
            except:
                pass
