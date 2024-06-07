from PyQt5.QtCore import QObject, pyqtSignal
import threading
import time


class MacTable(QObject):
    mac_table_update = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.timer = 30
        self.mac_table = {}  # Stores entries as {mac: {"port": port, "timer": timer}}
        self.timer_thread = None
        self.timer_thread_stop = False
        self.update_table_thread = threading.Thread(target=self.update_table, daemon=True)
        self.update_table_thread.start()

    # Method to update the table for GUI
    def update_table(self):
        while True:
            try:
                self.mac_table_update.emit()
                time.sleep(0.5)
            except:
                pass

    # Method to add an entry to the MAC table
    def add_entry(self, mac, port):
        self.mac_table[mac] = {"port": port, "timer": self.timer}

        if self.timer_thread is None:
            self.start_timer()

    # Method to remove an entry from the MAC table
    def remove_entry(self, mac):
        if mac in self.mac_table:
            del self.mac_table[mac]

    # Method to get the port of a MAC address, used when interface is down to remove all entries
    def remove_entry_interface(self, port):
        macs_to_remove = []
        for mac, entry in list(self.mac_table.items()):
            if entry["port"] == port:
                macs_to_remove.append(mac)

        for mac in macs_to_remove:
            self.remove_entry(mac)

    # Method to start the timer thread decrementing the time of each entry
    def start_timer(self):
        self.timer_thread = threading.Thread(target=self.timer_thread_function, daemon=True)
        self.timer_thread.start()

    def timer_thread_function(self):
        while True:
            time.sleep(1)
            macs_to_remove = []
            for mac, entry in list(self.mac_table.items()):
                entry["timer"] -= 1
                if entry["timer"] <= 0:
                    macs_to_remove.append(mac)

            for mac in macs_to_remove:
                self.remove_entry(mac)

    # Method to clear the MAC table, used when user clicks the clear button in GUI
    def clear_table(self):
        self.mac_table = {}

    # Method to refresh the timer of an entry, when same frame is received
    def refresh_timer(self, mac):
        if mac in self.mac_table:
            self.mac_table[mac]["timer"] = self.timer
