from gui import GUI
from stats import StatisticsManager
import sys
import psutil
from PyQt5 import QtWidgets


# Method to get all the Ethernet interfaces
def get_eth_interfaces():
    ethernet_interfaces = {}
    for interface, address in psutil.net_if_addrs().items():
        for addr in address:
            if psutil.net_if_stats()[interface].isup:
                ethernet_interfaces[interface] = addr.address
                break

    return ethernet_interfaces


def main():
    all_interfaces = get_eth_interfaces()
    stats_manager = StatisticsManager()
    gui = GUI(stats_manager, all_interfaces)

    app = QtWidgets.QApplication(sys.argv)
    SW1 = QtWidgets.QMainWindow()
    gui.setup_ui(SW1)
    SW1.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
