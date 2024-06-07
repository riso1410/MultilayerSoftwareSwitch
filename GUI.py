from PyQt5 import QtCore, QtGui, QtWidgets
import switch
import threading
import rule
import acl
from syslog import Syslog


def is_valid_ipv4(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for item in parts:
        if not item.isdigit() or not 0 <= int(item) <= 255:
            return False
    return True


def is_valid_mac(mac):
    parts = mac.split(":")
    if len(parts) != 6:
        return False
    for part in parts:
        if len(part) != 2 or not all(c in "0123456789ABCDEFabcdef" for c in part):
            return False
    return True


def is_valid_port(port):
    try:
        port = int(port)
        return 0 <= port <= 65535
    except ValueError:
        return False


class GUI(QtCore.QObject):

    def __init__(self, stats_manager, all_interfaces):
        super().__init__()
        self.syslog_obj = None
        self.stats_manager = stats_manager
        self.all_interfaces = all_interfaces
        # Class for ACL
        self.acl_obj = acl.AccessControlList()
        # Class for Switch which is main logic of forwarding frames
        self.switch = switch.Switch(stats_manager, self.acl_obj, self.syslog_obj)
        self.switch_thread = None
        self.port1_table = stats_manager.port1_stats
        self.port2_table = stats_manager.port2_stats
        self.row_rule = {}
        self.icmp_types = {
                                "Echo Reply": 0,
                                "Destination Unreachable": 3,
                                "Echo": 8,
                                "Time Exceeded": 11,
                            }

    def setup_ui(self, SW1):
        SW1.setObjectName("SW1")
        SW1.resize(1405, 856)
        self.MainWindow = QtWidgets.QWidget(SW1)
        self.MainWindow.setObjectName("MainWindow")

        self.MACTable = QtWidgets.QTableView(self.MainWindow)
        self.MACTable.setGeometry(QtCore.QRect(340, 80, 611, 351))
        self.MACTable.setObjectName("MAC_table")
        self.MACTable.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)

        self.Heading = QtWidgets.QLabel(self.MainWindow)
        self.Heading.setGeometry(QtCore.QRect(570, 20, 491, 41))
        font = QtGui.QFont()
        font.setPointSize(26)
        self.Heading.setFont(font)
        self.Heading.setObjectName("Heading")

        self.ClearTable = QtWidgets.QPushButton(self.MainWindow)
        self.ClearTable.setGeometry(QtCore.QRect(990, 230, 81, 31))
        self.ClearTable.setObjectName("ClearTable")

        self.MacTimer = QtWidgets.QSpinBox(self.MainWindow)
        self.MacTimer.setGeometry(QtCore.QRect(990, 130, 81, 31))
        self.MacTimer.setObjectName("MacTimer")

        self.TimerText = QtWidgets.QLabel(self.MainWindow)
        self.TimerText.setGeometry(QtCore.QRect(1000, 90, 61, 31))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.TimerText.setFont(font)
        self.TimerText.setObjectName("TimerText")

        self.Run = QtWidgets.QPushButton(self.MainWindow)
        self.Run.setGeometry(QtCore.QRect(340, 20, 171, 41))
        self.Run.setObjectName("Run")

        self.layoutWidget = QtWidgets.QWidget(self.MainWindow)
        self.layoutWidget.setGeometry(QtCore.QRect(10, 10, 290, 550))
        self.layoutWidget.setObjectName("layoutWidget")
        self.Group1 = QtWidgets.QVBoxLayout(self.layoutWidget)
        self.Group1.setContentsMargins(0, 0, 0, 0)
        self.Group1.setObjectName("Group1")
        self.Interface1 = QtWidgets.QLabel(self.layoutWidget)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.Interface1.setFont(font)
        self.Interface1.setContextMenuPolicy(QtCore.Qt.PreventContextMenu)
        self.Interface1.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.Interface1.setAlignment(QtCore.Qt.AlignCenter)
        self.Interface1.setObjectName("Interface1")
        self.Group1.addWidget(self.Interface1)

        self.ChooseInterfaceLeft = QtWidgets.QComboBox(self.layoutWidget)
        self.ChooseInterfaceLeft.setObjectName("ChooseInterfaceLeft")

        self.Group1.addWidget(self.ChooseInterfaceLeft)
        self.StatsTableLeft = QtWidgets.QTableView(self.layoutWidget)
        self.StatsTableLeft.setObjectName("StatsTableLeft")
        self.Group1.addWidget(self.StatsTableLeft)

        self.ResetStatsLeft = QtWidgets.QPushButton(self.layoutWidget)
        self.ResetStatsLeft.setContextMenuPolicy(QtCore.Qt.PreventContextMenu)
        self.ResetStatsLeft.setObjectName("ResetStatsLeft")

        self.Group1.addWidget(self.ResetStatsLeft)
        self.layoutWidget1 = QtWidgets.QWidget(self.MainWindow)
        self.layoutWidget1.setGeometry(QtCore.QRect(1100, 10, 290, 550))
        self.layoutWidget1.setObjectName("layoutWidget1")
        self.Group2 = QtWidgets.QVBoxLayout(self.layoutWidget1)
        self.Group2.setContentsMargins(0, 0, 0, 0)
        self.Group2.setObjectName("Group2")
        self.Interface2 = QtWidgets.QLabel(self.layoutWidget1)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.Interface2.setFont(font)
        self.Interface2.setContextMenuPolicy(QtCore.Qt.PreventContextMenu)
        self.Interface2.setAlignment(QtCore.Qt.AlignCenter)
        self.Interface2.setObjectName("Interface2")
        self.Group2.addWidget(self.Interface2)

        self.ChooseInterfaceRight = QtWidgets.QComboBox(self.layoutWidget1)
        self.ChooseInterfaceRight.setObjectName("comboBox_2")

        self.Group2.addWidget(self.ChooseInterfaceRight)
        self.StatsTableRight = QtWidgets.QTableView(self.layoutWidget1)
        self.StatsTableRight.setObjectName("StatsTableRight")
        self.Group2.addWidget(self.StatsTableRight)

        self.ResetStatsRight = QtWidgets.QPushButton(self.layoutWidget1)
        self.ResetStatsRight.setContextMenuPolicy(QtCore.Qt.PreventContextMenu)
        self.ResetStatsRight.setObjectName("ResetStatsRight")

        self.Group2.addWidget(self.ResetStatsRight)

        self.SetTimer = QtWidgets.QPushButton(self.MainWindow)
        self.SetTimer.setGeometry(QtCore.QRect(990, 170, 81, 31))
        self.SetTimer.setObjectName("SetTimer")

        self.SyslogText = QtWidgets.QLabel(self.MainWindow)
        self.SyslogText.setGeometry(QtCore.QRect(290, 500, 161, 24))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.SyslogText.setFont(font)
        self.SyslogText.setContextMenuPolicy(QtCore.Qt.PreventContextMenu)
        self.SyslogText.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.SyslogText.setAlignment(QtCore.Qt.AlignCenter)
        self.SyslogText.setObjectName("SyslogText")

        self.ConnectDisconnect = QtWidgets.QPushButton(self.MainWindow)
        self.ConnectDisconnect.setGeometry(QtCore.QRect(890, 490, 181, 41))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.ConnectDisconnect.setFont(font)
        self.ConnectDisconnect.setObjectName("ConnectDisconnect")

        self.SourceIPText = QtWidgets.QLabel(self.MainWindow)
        self.SourceIPText.setGeometry(QtCore.QRect(500, 450, 101, 24))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.SourceIPText.setFont(font)
        self.SourceIPText.setContextMenuPolicy(QtCore.Qt.PreventContextMenu)
        self.SourceIPText.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.SourceIPText.setAlignment(QtCore.Qt.AlignCenter)
        self.SourceIPText.setObjectName("SourceIPText")
        self.DestinationIPText = QtWidgets.QLabel(self.MainWindow)
        self.DestinationIPText.setGeometry(QtCore.QRect(690, 450, 151, 24))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.DestinationIPText.setFont(font)
        self.DestinationIPText.setContextMenuPolicy(QtCore.Qt.PreventContextMenu)
        self.DestinationIPText.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.DestinationIPText.setAlignment(QtCore.Qt.AlignCenter)
        self.DestinationIPText.setObjectName("DestinationIPText")

        self.SourceIP = QtWidgets.QTextEdit(self.MainWindow)
        self.SourceIP.setGeometry(QtCore.QRect(460, 500, 171, 31))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.SourceIP.setFont(font)
        self.SourceIP.setObjectName("SourceIP")

        self.DestinationIP = QtWidgets.QTextEdit(self.MainWindow)
        self.DestinationIP.setGeometry(QtCore.QRect(680, 500, 171, 31))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.DestinationIP.setFont(font)
        self.DestinationIP.setObjectName("DestinationIP")

        self.ACLText = QtWidgets.QLabel(self.MainWindow)
        self.ACLText.setGeometry(QtCore.QRect(580, 560, 161, 24))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.ACLText.setFont(font)
        self.ACLText.setContextMenuPolicy(QtCore.Qt.PreventContextMenu)
        self.ACLText.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.ACLText.setAlignment(QtCore.Qt.AlignCenter)
        self.ACLText.setObjectName("ACLText")

        self.ACLTable = QtWidgets.QTableWidget(self.MainWindow)
        self.ACLTable.setGeometry(QtCore.QRect(10, 600, 1261, 201))
        self.ACLTable.setObjectName("ACLTable")

        # Setup column count and headers
        columnHeaders = ['Inter', 'IN/OUT', 'A', 'ICMP Type', 'Src IP', 'Dst IP', 'Src MAC', 'Dst MAC', 'S Port',
                         'D Port',
                         'Select']
        self.ACLTable.setColumnCount(len(columnHeaders))
        self.ACLTable.setHorizontalHeaderLabels(columnHeaders)
        self.ACLTable.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.add_rule()

        self.ClearACL = QtWidgets.QPushButton(self.MainWindow)
        self.ClearACL.setGeometry(QtCore.QRect(1290, 700, 101, 41))
        self.ClearACL.setObjectName("ClearACL")
        self.RemoveRule = QtWidgets.QPushButton(self.MainWindow)
        self.RemoveRule.setGeometry(QtCore.QRect(1290, 650, 101, 41))
        self.RemoveRule.setObjectName("RemoveRule")
        self.AddRule = QtWidgets.QPushButton(self.MainWindow)
        self.AddRule.setGeometry(QtCore.QRect(1290, 600, 101, 41))
        self.AddRule.setObjectName("AddRule")
        self.UpButton = QtWidgets.QPushButton(self.MainWindow)
        self.UpButton.setGeometry(QtCore.QRect(1290, 750, 41, 41))
        self.UpButton.setObjectName("UpButton")
        self.DownButton = QtWidgets.QPushButton(self.MainWindow)
        self.DownButton.setGeometry(QtCore.QRect(1350, 750, 41, 41))
        self.DownButton.setObjectName("DownButton")
        font = QtGui.QFont()
        font.setPointSize(22)
        self.UpButton.setFont(font)
        self.DownButton.setFont(font)
        SW1.setCentralWidget(self.MainWindow)
        self.menubar = QtWidgets.QMenuBar(SW1)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1405, 26))
        self.menubar.setObjectName("menubar")
        SW1.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(SW1)
        self.statusbar.setObjectName("statusbar")
        SW1.setStatusBar(self.statusbar)

        # Connections
        self.set_scrolls()
        self.update_port_stats('port1', self.port1_table)
        self.update_port_stats('port2', self.port2_table)

        # Buttons
        self.Run.clicked.connect(self.start_switch)
        self.ResetStatsLeft.clicked.connect(self.clear_stats1)
        self.ResetStatsRight.clicked.connect(self.clear_stats2)
        self.SetTimer.clicked.connect(self.mac_table_set_timer)
        self.ClearTable.clicked.connect(self.switch.mac_table_obj.clear_table)
        self.stats_manager.stats_update.connect(self.update_stats)
        self.switch.mac_table_obj.mac_table_update.connect(self.update_mac_table)
        self.AddRule.clicked.connect(self.load_rule)
        self.RemoveRule.clicked.connect(self.remove_rule)
        self.ClearACL.clicked.connect(self.clear_rules)
        self.UpButton.clicked.connect(self.move_up)
        self.DownButton.clicked.connect(self.move_down)
        self.ConnectDisconnect.clicked.connect(self.connect_disconnect)

        self.translate_ui(SW1)
        QtCore.QMetaObject.connectSlotsByName(SW1)

    def translate_ui(self, SW1):
        _translate = QtCore.QCoreApplication.translate
        SW1.setWindowTitle(_translate("SW1", "Switch"))
        self.Heading.setText(_translate("SW1", "L2 MULTILAYER SWITCH"))
        self.ClearTable.setText(_translate("SW1", "Clear Table"))
        self.TimerText.setText(_translate("SW1", "Timer"))
        self.Run.setText(_translate("SW1", "Run"))
        self.Interface1.setText(_translate("SW1", "Interface 1"))
        self.ResetStatsLeft.setText(_translate("SW1", "Reset Statistics"))
        self.Interface2.setText(_translate("SW1", "Interface 2"))
        self.ResetStatsRight.setText(_translate("SW1", "Reset Statistics"))
        self.SetTimer.setText(_translate("SW1", "Set Time"))
        self.SyslogText.setText(_translate("SW1", "Syslog"))
        self.ConnectDisconnect.setText(_translate("SW1", "Connect"))
        self.SourceIPText.setText(_translate("SW1", "Source IP"))
        self.DestinationIPText.setText(_translate("SW1", "Destination IP"))
        self.ACLText.setText(_translate("SW1", "ACL"))
        self.ClearACL.setText(_translate("SW1", "Clear ACL"))
        self.RemoveRule.setText(_translate("SW1", "Remove Rule"))
        self.AddRule.setText(_translate("SW1", "Add Rule"))
        self.UpButton.setText(_translate("SW1", "▲"))
        self.DownButton.setText(_translate("SW1", "▼"))

    def start_switch(self):
        port1 = self.ChooseInterfaceLeft.currentText()
        port2 = self.ChooseInterfaceRight.currentText()

        if port1 == port2:
            return

        self.switch_thread = threading.Thread(target=self.switch.start, args=(port1, port2), daemon=True)
        self.switch_thread.start()
        self.Run.setText('Running')
        self.Run.clicked.disconnect(self.start_switch)

    def clear_stats1(self):
        if self.syslog_obj:
            self.syslog_obj.send_message(f'Interface 1 statistics cleared', 'INFO')
        self.stats_manager.clear_statistics('port1')

    def clear_stats2(self):
        if self.syslog_obj:
            self.syslog_obj.send_message(f'Interface 2 statistics cleared', 'INFO')
        self.stats_manager.clear_statistics('port2')

    def update_stats(self):
        self.update_port_stats('port1', self.port1_table)
        self.update_port_stats('port2', self.port2_table)

    def set_scrolls(self):
        for interface in self.all_interfaces:
            self.ChooseInterfaceLeft.addItem(interface)
            self.ChooseInterfaceRight.addItem(interface)

    def update_port_stats(self, port, data):
        table = QtGui.QStandardItemModel()
        table.setHorizontalHeaderLabels(["Protocol", "Count"])
        for protocol, value in data.items():
            table.appendRow([QtGui.QStandardItem(protocol), QtGui.QStandardItem(str(value))])

        if port == 'port1':
            self.StatsTableLeft.setModel(table)
            self.StatsTableLeft.resizeColumnsToContents()
            self.StatsTableLeft.resizeRowsToContents()
            self.StatsTableLeft.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        elif port == 'port2':
            self.StatsTableRight.setModel(table)
            self.StatsTableRight.resizeColumnsToContents()
            self.StatsTableRight.resizeRowsToContents()
            self.StatsTableRight.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)

    def update_mac_table(self):
        model = QtGui.QStandardItemModel()
        self.MACTable.setModel(model)
        model.setHorizontalHeaderLabels(['MAC Address', 'Port', 'Timer'])

        for mac, entry in self.switch.mac_table_obj.mac_table.items():
            mac_item = QtGui.QStandardItem(mac)
            port_item = QtGui.QStandardItem(entry["port"])
            timer_item = QtGui.QStandardItem(str(entry["timer"]))
            model.appendRow([mac_item, port_item, timer_item])

        self.MACTable.resizeColumnsToContents()

    def mac_table_set_timer(self):
        try:
            timer = self.MacTimer.value()
            if timer >= 1:
                if self.syslog_obj:
                    self.syslog_obj.send_message(f'MAC Table timer set to {timer}', 'INFO')
                self.switch.mac_table_obj.timer = timer
        except:
            return

    def load_rule(self):
        row_count = self.ACLTable.rowCount()
        for row in range(row_count):
            checkBoxWidget = self.ACLTable.cellWidget(row, 10)
            checkBox = checkBoxWidget.layout().itemAt(0).widget()
            if checkBox.isChecked():
                interface = self.ACLTable.cellWidget(row, 0).currentText()
                direction = self.ACLTable.cellWidget(row, 1).currentText()
                action = self.ACLTable.cellWidget(row, 2).currentText()
                icmp_type = self.ACLTable.cellWidget(row, 3).currentText()

                if interface == 'Select' or direction == 'Select' or action == 'Select':
                    return

                src_ip_widget = self.ACLTable.item(row, 4)
                src_ip = src_ip_widget.text() if src_ip_widget is not None and is_valid_ipv4(
                    src_ip_widget.text()) else 'any'

                dst_ip_widget = self.ACLTable.item(row, 5)
                dst_ip = dst_ip_widget.text() if dst_ip_widget is not None and is_valid_ipv4(
                    dst_ip_widget.text()) else 'any'

                src_mac_widget = self.ACLTable.item(row, 6)
                src_mac = src_mac_widget.text() if src_mac_widget is not None and is_valid_mac(
                    src_mac_widget.text()) else 'any'

                dst_mac_widget = self.ACLTable.item(row, 7)
                dst_mac = dst_mac_widget.text() if dst_mac_widget is not None and is_valid_mac(
                    dst_mac_widget.text()) else 'any'

                src_port_widget = self.ACLTable.item(row, 8)
                src_port = src_port_widget.text() if src_port_widget is not None and is_valid_port(
                    src_port_widget.text()) else 'any'

                dst_port_widget = self.ACLTable.item(row, 9)
                dst_port = dst_port_widget.text() if dst_port_widget is not None and is_valid_port(
                    dst_port_widget.text()) else 'any'

                created_rule = rule.Rule()
                if icmp_type in self.icmp_types:
                    icmp_type = self.icmp_types[icmp_type]
                else:
                    if icmp_type == 'any':
                        icmp_type = 'any'
                    elif icmp_type == 'none':
                        icmp_type = 'none'

                created_rule.set_rules(0, interface, direction, action, src_mac, dst_mac,
                                       src_ip, dst_ip, src_port, dst_port, icmp_type)
                self.row_rule[row] = created_rule
                self.acl_obj.add_rule(created_rule)
                if self.syslog_obj:
                    self.syslog_obj.send_message(f'Rule added: {created_rule}', 'NOTICE')

                if row == row_count - 1:
                    self.add_rule()

        self.deselect_all_checkboxes()

    def remove_rule(self):
        rows_to_delete = []

        for row in range(self.ACLTable.rowCount() - 1, -1, -1):
            checkBoxWidget = self.ACLTable.cellWidget(row, 10)
            if checkBoxWidget is not None:
                checkBox = checkBoxWidget.layout().itemAt(0).widget()
                if checkBox.isChecked():
                    if row == self.ACLTable.rowCount() - 1 or self.ACLTable.rowCount() == 1:
                        continue
                    rows_to_delete.append(row)

        for row in sorted(rows_to_delete, reverse=True):
            self.ACLTable.removeRow(row)
            self.acl_obj.remove_rule(self.row_rule[row])
            if self.syslog_obj:
                self.syslog_obj.send_message(f'Rule removed: {self.row_rule[row]}', 'NOTICE')

            del self.row_rule[row]

        new_row_rule = {}
        for newRow, oldRow in enumerate(sorted(self.row_rule.keys())):
            new_row_rule[newRow] = self.row_rule[oldRow]
            new_row_rule[newRow].priority = newRow

        self.row_rule = new_row_rule
        self.update_priority()

    def clear_rules(self):
        self.ACLTable.clearContents()
        self.ACLTable.setRowCount(0)
        self.acl_obj.remove_all_rules()
        self.row_rule.clear()
        self.add_rule()

    def add_rule(self):
        rowIndex = self.ACLTable.rowCount()
        self.ACLTable.insertRow(rowIndex)

        for i in range(4):
            combo_box = None
            if i == 0:
                combo_box = QtWidgets.QComboBox()
                combo_box.addItem("Select")
                combo_box.addItems(self.all_interfaces)

            elif i == 1:
                combo_box = QtWidgets.QComboBox()
                combo_box.addItems(["Select", "IN", "OUT"])

            elif i == 2:
                combo_box = QtWidgets.QComboBox()
                combo_box.addItems(["Select", "Permit", "Deny"])

            elif i == 3:
                combo_box = QtWidgets.QComboBox()
                combo_box.addItems(
                    ["any", "none", "Echo Reply", "Destination Unreachable", "Echo",
                     "Time Exceeded"])

            self.ACLTable.setCellWidget(rowIndex, i, combo_box)

        for i in range(4, 10):
            self.ACLTable.item(rowIndex, i)

        checkBox = QtWidgets.QCheckBox()
        checkBoxWidget = QtWidgets.QWidget()
        checkBoxLayout = QtWidgets.QHBoxLayout(checkBoxWidget)
        checkBoxLayout.addWidget(checkBox)
        checkBoxLayout.setAlignment(QtCore.Qt.AlignCenter)
        checkBoxLayout.setContentsMargins(0, 0, 0, 0)
        checkBoxWidget.setLayout(checkBoxLayout)

        self.ACLTable.setCellWidget(rowIndex, 10, checkBoxWidget)

    def move_up(self):
        selected_rows = [row for row in range(self.ACLTable.rowCount())
                         if self.ACLTable.cellWidget(row, 10).layout().itemAt(0).widget().isChecked()]

        if len(selected_rows) == 1 and selected_rows[0] != self.ACLTable.rowCount() - 1:
            row = selected_rows[0]
            if row > 0:
                self.ACLTable.insertRow(row - 1)
                for col in range(self.ACLTable.columnCount()):
                    item = self.ACLTable.takeItem(row + 1, col)
                    widget = self.ACLTable.cellWidget(row + 1, col)

                    self.ACLTable.setItem(row - 1, col, item)
                    self.ACLTable.setCellWidget(row - 1, col, widget)

                self.ACLTable.removeRow(row + 1)
                self.row_rule[row - 1], self.row_rule[row] = self.row_rule[row], self.row_rule[row - 1]
                self.update_priority()

    def deselect_all_checkboxes(self):
        for row in range(self.ACLTable.rowCount()):
            checkBoxWidget = self.ACLTable.cellWidget(row, 10)
            if checkBoxWidget:
                checkBox = checkBoxWidget.layout().itemAt(0).widget()
                checkBox.setChecked(False)

    def move_down(self):
        selected_rows = [row for row in range(self.ACLTable.rowCount())
                         if self.ACLTable.cellWidget(row, 10).layout().itemAt(0).widget().isChecked()]

        selected_rows.reverse()

        if len(selected_rows) == 1 and selected_rows[0] != self.ACLTable.rowCount() - 1:
            row = selected_rows[0]
            if row < self.ACLTable.rowCount() - 1:
                self.ACLTable.insertRow(row + 2)
                for col in range(self.ACLTable.columnCount()):
                    item = self.ACLTable.takeItem(row, col)
                    widget = self.ACLTable.cellWidget(row, col)

                    self.ACLTable.setItem(row + 2, col, item)
                    self.ACLTable.setCellWidget(row + 2, col, widget)

                self.ACLTable.removeRow(row)
                self.row_rule[row + 1], self.row_rule[row] = self.row_rule[row], self.row_rule[row + 1]

            self.update_priority()

    def update_priority(self):
        self.acl_obj.set_rule_priority(self.row_rule)

    def connect_disconnect(self):
        src_ip = self.SourceIP.toPlainText().strip()
        dst_ip = self.DestinationIP.toPlainText().strip()

        if not src_ip or not dst_ip:
            return

        if self.ConnectDisconnect.text() == 'Connect':
            try:
                self.syslog_obj = Syslog(src_ip, dst_ip, switch=self.switch)
                self.syslog_obj.send_message('Syslog connected', 'INFO')
                self.ConnectDisconnect.setText('Disconnect')
            except:
                del self.syslog_obj
                self.ConnectDisconnect.setText('Connect')
        else:
            self.syslog_obj.send_message('Syslog disconnected', 'INFO')
            del self.syslog_obj
            self.ConnectDisconnect.setText('Connect')
