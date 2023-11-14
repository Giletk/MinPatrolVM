import logging
import sys

import paramiko
import psycopg2
from PyQt5.QtWidgets import *


class QTextEditLogger(logging.Handler):
    def __init__(self, parent):
        super().__init__()
        self.widget = QPlainTextEdit(parent)
        self.widget.setReadOnly(True)

    def emit(self, record):
        msg = self.format(record)
        self.widget.appendPlainText(msg)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("MinPatrolVM")
        self.setGeometry(100, 100, 800, 600)

        # SSH Settings Group
        ssh_group = QGroupBox("SSH Settings")
        ssh_layout = QFormLayout()
        self.ssh_host = QLineEdit("192.168.94.109")
        self.ssh_port = QLineEdit("22")
        self.ssh_username = QLineEdit("ubu")
        self.ssh_password = QLineEdit()
        self.ssh_password.setEchoMode(QLineEdit.Password)
        ssh_layout.addRow("Host:", self.ssh_host)
        ssh_layout.addRow("Port:", self.ssh_port)
        ssh_layout.addRow("Username:", self.ssh_username)
        ssh_layout.addRow("Password:", self.ssh_password)
        ssh_group.setLayout(ssh_layout)

        # PostgreSQL Settings Group
        db_group = QGroupBox("PostgreSQLDB Settings")
        db_layout = QFormLayout()
        self.db_host = QLineEdit("127.0.0.1")
        self.db_port = QLineEdit("5432")
        self.db_name = QLineEdit("audit")
        self.db_user = QLineEdit("postgres")
        self.db_password = QLineEdit()
        self.db_password.setEchoMode(QLineEdit.Password)
        db_layout.addRow("Host:", self.db_host)
        db_layout.addRow("Port:", self.db_port)
        db_layout.addRow("DB Name:", self.db_name)
        db_layout.addRow("User:", self.db_user)
        db_layout.addRow("Password:", self.db_password)
        db_group.setLayout(db_layout)

        # Run Button
        run_button = QPushButton("Run")
        run_button.clicked.connect(self.run_button_clicked)

        # Get Results Button
        self.w = None
        get_results_button = QPushButton("Get Results")
        get_results_button.clicked.connect(self.get_results_button_clicked)

        # Log Area
        logger_box = QTextEditLogger(self)

        # Layout
        main_layout = QVBoxLayout()
        main_layout.addWidget(ssh_group)
        main_layout.addWidget(db_group)
        main_layout.addWidget(run_button)
        main_layout.addWidget(logger_box.widget)
        main_layout.addWidget(get_results_button)

        central_widget = QWidget()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

        # Logger definition
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.INFO)
        logger_box.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(logger_box)

        file_handler = logging.FileHandler('ssh_log.txt')
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(file_handler)

    def get_results_button_clicked(self):
        if not all([
            self.db_host.text(),
            self.db_port.text(),
            self.db_name.text(),
            self.db_user.text(),
            self.db_password.text()
        ]):
            self.logger.warning("Please fill in all DB settings fields.")
        else:
            if self.w is None:
                self.w = DataWindow(self.db_host.text(), self.db_port.text(),
                                    self.db_name.text(), self.db_user.text(),
                                    self.db_password.text())
            elif self.w.needs_reopen():
                self.w = DataWindow(self.db_host.text(), self.db_port.text(),
                                    self.db_name.text(), self.db_user.text(),
                                    self.db_password.text())

            self.w.show()

    def run_button_clicked(self):
        if not all([
            self.ssh_host.text(),
            self.ssh_port.text(),
            self.ssh_username.text(),
            self.ssh_password.text(),
            self.db_host.text(),
            self.db_port.text(),
            self.db_name.text(),
            self.db_user.text(),
            self.db_password.text()
        ]):
            self.logger.warning("Please fill in all required fields.")
        else:
            self.run_scan()

    def closeEvent(self, event):
        for window_ in QApplication.topLevelWidgets():
            window_.close()

    def create_table_if_not_exist(self, conn, cursor):
        try:
            create_scans_table_query = """
            CREATE TABLE IF NOT EXISTS scans (
                ip varchar(15) PRIMARY KEY,
                distr_group varchar(254),
                distr varchar(254),                
                os_version varchar(50),
                architecture varchar(50)
            );
            """
            cursor.execute(create_scans_table_query)
            conn.commit()
            self.logger.debug("Table 'scans' created or already exist.")
        except Exception as e:
            conn.rollback()
            self.logger.error(f"Error creating tables: {e}")

    def execute_ssh_command(self, ssh, command):
        try:
            stdin, stdout, stderr = ssh.exec_command(command)
            output = stdout.read().decode()
            return output
        except Exception as e:
            self.logger.error(f"Failed to execute SSH command: {str(e)}")
            return None

    def get_remote_os_info(self, ssh):
        try:
            os_info = self.execute_ssh_command(ssh, "cat /etc/os-release").strip()
            distr = "Unknown"
            distr_group = "Unknown"
            for line in os_info.split("\n"):
                line = line.lower()
                if line.startswith("id_like="):
                    if "debian" in line:
                        distr_group = "Debian"
                    elif "ubuntu" in line:
                        distr_group = "Ubuntu"
                    elif "manjaro" in line:
                        distr_group = "Manjaro"
                    else:
                        distr_group = "Unknown Linux"
                if line.startswith("id="):
                    distr = line.split("=")[1]
            os_version = self.execute_ssh_command(ssh, 'uname -r').strip()
            arch = self.execute_ssh_command(ssh, 'uname -m').strip()
            return distr_group, distr, os_version, arch
        except Exception as e:
            self.logger.error(f"Error occured while retrieving OS info: {str(e)}")

    def run_scan(self):
        try:
            ssh_host = self.ssh_host.text()
            ssh_port = self.ssh_port.text()
            ssh_username = self.ssh_username.text()
            ssh_password = self.ssh_password.text()
            try:
                # SSH Connection
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ssh_host, int(ssh_port), ssh_username, ssh_password)

            except Exception as e:
                self.logger.error(f"Failed to connect via SSH: {str(e)}")
                return
            self.logger.info(f"Connected to {ssh_host} via SSH")
            # Detect OS and get information
            distr_group, distr, os_version, arch = self.get_remote_os_info(ssh)

            # Logging the SSH commands
            self.logger.info(f"Distributive family: {distr_group}")
            self.logger.info(f"Distributive: {distr}")
            self.logger.info(f"OS Version: {os_version}")
            self.logger.info(f"Architecture: {arch}")

            # Database Connection
            conn = psycopg2.connect(
                host=self.db_host.text(),
                port=self.db_port.text(),
                dbname=self.db_name.text(),
                user=self.db_user.text(),
                password=self.db_password.text()
            )
            cursor = conn.cursor()

            self.create_table_if_not_exist(conn, cursor)
            # Insert OS information into the PostgreSQL database
            cursor.execute(
                "INSERT INTO scans (ip, distr_group, distr, os_version, architecture) VALUES (%s, %s, %s, %s, %s)",
                (ssh_host, distr_group, distr, os_version, arch))
            conn.commit()

            cursor.close()
            conn.close()

            ssh.close()

        except psycopg2.OperationalError as e:
            self.logger.error(f"Failed to connect to DB: {e}")

        except Exception as e:
            self.logger.error(f"An error occurred: {e}", exc_info=True)


class DataWindow(QWidget):
    def __init__(self, db_host, db_port, db_name, db_user, db_password):
        super().__init__()
        self.setGeometry(150, 150, 600, 400)
        self.setWindowTitle("MinPatrolVM    Get info")

        self.db_host = db_host
        self.db_port = db_port
        self.db_name = db_name
        self.db_user = db_user
        self.db_password = db_password
        
        # Search Options Group
        search_group = QGroupBox("Search Options")
        search_layout = QFormLayout()
        self.search_ip = QLineEdit()
        self.search_group = QLineEdit()
        self.search_distr = QLineEdit()
        self.search_version = QLineEdit()
        self.search_arch = QLineEdit()
        search_layout.addRow("Host:", self.search_ip)
        search_layout.addRow("Distro family:", self.search_group)
        search_layout.addRow("Distro name:", self.search_distr)
        search_layout.addRow("OS version:", self.search_version)
        search_layout.addRow("Arch:", self.search_arch)
        search_group.setLayout(search_layout)

        # Search Button
        search_button = QPushButton("Search")
        search_button.clicked.connect(self.search_button_clicked)

        # Warning Label
        self.warning_label = QLabel()

        # Table
        self.table = QTableWidget(self)
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["ip", "distr_group", "distr", "os_version", "architecture"])

        # Layout
        main_layout = QVBoxLayout()
        main_layout.addWidget(search_group)
        main_layout.addWidget(search_button)
        main_layout.addWidget(self.warning_label)
        main_layout.addWidget(self.table)
        self.setLayout(main_layout)

        # Query dict
        self.query_dict={self.search_ip: "ip",
                         self.search_group: "distr_group",
                         self.search_distr: "distr",
                         self.search_version: "os_version",
                         self.search_arch: "architecture"}
        
    def search_button_clicked(self):
        try:
            conn = psycopg2.connect(
                host=self.db_host,
                port=self.db_port,
                dbname=self.db_name,
                user=self.db_user,
                password=self.db_password
            )
        except Exception as e:
            self.warning_label.setText("Something went wrong! Close this window and check if DB settings are correct")
            return

        # Creating Query
        query = "SELECT * FROM scans"
        first_flag = 1
        for parameter in [self.search_ip, self.search_group, self.search_distr,
                          self.search_version, self.search_arch]:
            if parameter.text():
                if first_flag:
                    query += " WHERE"
                if not first_flag:
                    query += " AND"
                query += f" {self.query_dict[parameter]} LIKE '%{parameter.text()}%'"
        print(query)

        # Getting info from DB
        cursor = conn.cursor()
        cursor.execute(query)
        data = cursor.fetchall()
        print(data)
        # Display the data in the table widget
        self.table.setRowCount(len(data))
        for row, record in enumerate(data):
            for col, value in enumerate(record):
                item = QTableWidgetItem(str(value))
                self.table.setItem(row, col, item)

        cursor.close()
        conn.close()

    def needs_reopen(self):
        return bool(self.warning_label.text())


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
