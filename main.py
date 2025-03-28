import os, binascii, struct, logging, datetime, sys
import requests
from bsddb3.db import DB, DBError, DB_BTREE, DB_RDONLY, DB_THREAD
from PyQt5.QtWidgets import (
    QApplication, QVBoxLayout, QLabel, QPushButton,
    QFileDialog, QMainWindow, QWidget, QTextEdit, QMessageBox
)
from PyQt5.QtCore import Qt, QRunnable, QThreadPool, pyqtSignal, QObject
from PyQt5.QtGui import QIcon, QPixmap, QFont

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class SerializationError(Exception):
    pass

class BCDataStream:
    def __init__(self):
        self.input = None
        self.read_cursor = 0

    def clear(self):
        self.input = None
        self.read_cursor = 0

    def write(self, b):
        if self.input is None:
            self.input = b
        else:
            self.input += b

    def read_bytes(self, length):
        if self.input is None or self.read_cursor + length > len(self.input):
            raise SerializationError("Attempt to read past end of buffer")
        result = self.input[self.read_cursor:self.read_cursor + length]
        self.read_cursor += length
        return result

    def read_string(self):
        length = self.read_compact_size()
        return self.read_bytes(length).decode('ascii')

    def read_uint32(self):
        return self._read_num('<I')

    def read_compact_size(self):
        if self.read_cursor >= len(self.input):
            raise SerializationError("Attempt to read past end of buffer")
        size = self.input[self.read_cursor]
        self.read_cursor += 1
        if size == 253:
            return self._read_num('<H')
        elif size == 254:
            return self._read_num('<I')
        elif size == 255:
            return self._read_num('<Q')
        return size

    def _read_num(self, fmt):
        s = struct.calcsize(fmt)
        if self.read_cursor + s > len(self.input):
            raise SerializationError("Attempt to read past end of buffer")
        result, = struct.unpack_from(fmt, self.input, self.read_cursor)
        self.read_cursor += s
        return result

def open_wallet(walletfile):
    db = DB()
    try:
        db.open(walletfile, "main", DB_BTREE, DB_RDONLY | DB_THREAD)
    except DBError as e:
        raise RuntimeError(f"Failed to open wallet file: {e}")
    return db

def parse_wallet(db):
    json_db = {}
    addresses = []
    kds = BCDataStream()
    vds = BCDataStream()
    for key, value in db.items():
        kds.clear()
        kds.write(key)
        vds.clear()
        vds.write(value)
        try:
            item_type = kds.read_string()
            if item_type == "mkey":
                enc_key_len = vds.read_compact_size()
                enc_key = binascii.hexlify(vds.read_bytes(enc_key_len)).decode()
                salt_len = vds.read_compact_size()
                salt = binascii.hexlify(vds.read_bytes(salt_len)).decode()
                vds.read_uint32()
                rounds = vds.read_uint32()
                json_db['master_key'] = enc_key
                json_db['salt'] = salt
                json_db['rounds'] = rounds
            elif item_type == "name":
                address = kds.read_string()
                addresses.append(address)
        except Exception as e:
            continue
    if 'master_key' not in json_db:
        raise RuntimeError("Wallet is not encrypted.")
    json_db['addresses'] = addresses
    return json_db

def get_address_balances(addresses):
    try:
        address_list = '|'.join(addresses)
        url = f"https://blockchain.info/balance?active={address_list}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        balances = []
        for address in addresses:
            balance_info = data.get(address, {})
            balances.append({
                'address': address,
                'final_balance': balance_info.get('final_balance', 0) / 1e8,
                'n_tx': balance_info.get('n_tx', 0),
                'total_received': balance_info.get('total_received', 0) / 1e8
            })
        return balances
    except Exception:
        return []

class WorkerSignals(QObject):
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

class ParserWorker(QRunnable):
    def __init__(self, filepaths):
        super().__init__()
        self.filepaths = filepaths
        self.signals = WorkerSignals()

    def run(self):
        results = {}
        try:
            for filepath in self.filepaths:
                filename = os.path.basename(filepath)
                try:
                    db = open_wallet(filepath)
                    json_db = parse_wallet(db)
                    bitcoin_format = "$bitcoin${}$${}$${}$${}$${}$2$00$2$00".format(
                        len(json_db['master_key']), json_db['master_key'],
                        len(json_db['salt']), json_db['salt'], json_db['rounds']
                    )
                    addresses = json_db.get('addresses', [])
                    balances = get_address_balances(addresses)
                    results[filename] = {
                        'bitcoin_format': bitcoin_format,
                        'addresses': balances,
                        'master_key': json_db['master_key'],
                        'salt': json_db['salt'],
                        'rounds': json_db['rounds']
                    }
                except RuntimeError as e:
                    results[filename] = {'error': str(e)}
            self.signals.finished.emit(results)
        except Exception as e:
            self.signals.error.emit(str(e))

class WalletClient(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Bitcoin Wallet Parser (Local)")
        self.setGeometry(300, 300, 850, 700)
        self.thread_pool = QThreadPool()
        self.init_ui()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(10, 10, 10, 10)

        title = QLabel("Bitcoin Wallet Parser")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Arial", 16, QFont.Bold))
        layout.addWidget(title)

        self.status_label = QLabel("Select wallet.dat files for parsing.")
        self.status_label.setStyleSheet("color: gray;")
        layout.addWidget(self.status_label)

        self.select_button = QPushButton("Select Files")
        self.select_button.clicked.connect(self.select_files)
        layout.addWidget(self.select_button)

        self.parse_button = QPushButton("Parse Wallets")
        self.parse_button.setEnabled(False)
        self.parse_button.clicked.connect(self.parse_wallets)
        layout.addWidget(self.parse_button)

        self.result_area = QTextEdit()
        self.result_area.setFont(QFont("Courier New", 10))
        self.result_area.setStyleSheet("background-color: #f0f0f0;")
        layout.addWidget(self.result_area)

        central_widget.setLayout(layout)

    def select_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select wallet.dat Files", "", "Dat Files (*.dat);;All Files (*.*)")
        if files:
            self.filepaths = files
            self.status_label.setText(f"{len(files)} files selected.")
            self.parse_button.setEnabled(True)

    def parse_wallets(self):
        self.result_area.clear()
        self.status_label.setText("Parsing files, please wait...")
        worker = ParserWorker(self.filepaths)
        worker.signals.finished.connect(self.on_parsed)
        worker.signals.error.connect(lambda e: self.status_label.setText(f"Error: {e}"))
        self.thread_pool.start(worker)

    def on_parsed(self, results):
        report = "===== Bitcoin Wallet Parsing Report =====\n"
        for i, (filename, data) in enumerate(results.items(), 1):
            report += f"\n[{i}] File: {filename}\n"
            if 'error' in data:
                report += f"Error: {data['error']}\n"
                continue
            report += f"Bitcoin Format: {data['bitcoin_format']}\n\n"
            report += "{:<4} {:<34} {:>14} {:>8} {:>16}\n".format(
                "No.", "Address", "Balance(BTC)", "TxCount", "TotalRecv(BTC)"
            )
            for idx, addr in enumerate(data['addresses'], 1):
                report += "{:<4} {:<34} {:>14.8f} {:>8} {:>16.8f}\n".format(
                    idx,
                    addr['address'],
                    addr['final_balance'],
                    addr['n_tx'],
                    addr['total_received']
                )
            report += f"\nMaster Key: {data['master_key']}\n"
            report += f"Salt: {data['salt']}\n"
            report += f"Rounds: {data['rounds']}\n"
            report += "-" * 50 + "\n"

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report += f"\nReport generated at {timestamp}\n"
        self.result_area.setText(report)
        self.status_label.setText("Parsing completed.")
        QMessageBox.information(self, "Done", "Wallet parsing completed successfully!")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    client = WalletClient()
    client.show()
    sys.exit(app.exec_())
