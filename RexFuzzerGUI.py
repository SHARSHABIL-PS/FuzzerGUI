import sys
import os
import threading
import requests
import time
import re
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QLabel,
    QFileDialog, QLineEdit, QSpinBox, QCheckBox, QComboBox, QMessageBox, QProgressBar
)
from PyQt6.QtGui import QFont, QTextCursor, QColor, QAction, QIcon
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject

WAFS = {
    "cloudflare": r"cloudflare",
    "sucuri": r"sucuri",
    "incapsula": r"incap_ses",
    "akamai": r"akamai|akamai",
    "f5": r"bigip|f5\-",
    "barracuda": r"barracuda",
    "sitelock": r"sitelock",
    "wzws": r"wzws",
}
ERROR_PATTERNS = [
    r"not found",
    r"404",
    r"the page you are looking for",
    r"page not found",
    r"does not exist",
    r"no such",
]
UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) RexFuzz/2025",
    "Mozilla/5.0 (X11; Linux x86_64) RexFuzz/2025",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) RexFuzz/2025",
]
requests.packages.urllib3.disable_warnings()
os.environ["QT_FONT_DPI"] = "96"

class Signals(QObject):
    log = pyqtSignal(str, str)
    progress = pyqtSignal(int)
    finished = pyqtSignal(float)
    status = pyqtSignal(str)
    waf = pyqtSignal(str)
    save = pyqtSignal(str)
    error = pyqtSignal(str)

signals = Signals()

class FuzzerThread(threading.Thread):
    def __init__(self, url, wordlist, threads, timeout, ua, proxy, only_good, stop_flag, results_file, log_file, filter_codes):
        threading.Thread.__init__(self)
        self.url = url
        self.wordlist = wordlist
        self.threads = threads
        self.timeout = timeout
        self.ua = ua
        self.proxy = proxy
        self.only_good = only_good
        self.stop_flag = stop_flag
        self.results_file = results_file
        self.log_file = log_file
        self.filter_codes = filter_codes
        self.results = []
        self.errors = []
        self.seen_sizes = {}
        self.total = len(wordlist)
        self.done = 0
        self.start_time = time.time()

    def run(self):
        def worker(urls):
            session = requests.Session()
            session.headers["User-Agent"] = self.ua
            if self.proxy:
                session.proxies = {"http": self.proxy, "https": self.proxy}
            for u in urls:
                if self.stop_flag.is_set():
                    return
                try:
                    resp = session.get(u, timeout=self.timeout, allow_redirects=False, verify=False)
                    code = resp.status_code
                    text = resp.text or ""
                    length = len(resp.content)
                    loc = resp.headers.get("Location")
                    waf = self.detect_waf(resp)
                    clr = self.code_color(code)
                    if self.is_interesting(code, text, u, length, loc):
                        if not self.only_good or code in self.filter_codes:
                            self.append_result(code, u, length, loc, waf, clr)
                            self.append_save(code, u, length, loc, waf)
                    self.done += 1
                    signals.progress.emit(self.done)
                    if waf:
                        signals.waf.emit(waf)
                except Exception as e:
                    self.append_log(f"{u}: {e}")
        urls = self.make_urls(self.url, self.wordlist)
        chunks = [urls[i::self.threads] for i in range(self.threads)]
        threads = []
        for chunk in chunks:
            t = threading.Thread(target=worker, args=(chunk,))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        signals.finished.emit(time.time() - self.start_time)

    def make_urls(self, base, words):
        out = []
        if "{FUZZ}" in base:
            for w in words:
                out.append(base.replace("{FUZZ}", w))
        else:
            if base[-1] != "/":
                base += "/"
            for w in words:
                out.append(base + w)
        return out

    def is_fake_200(self, code, text, url, length):
        if code != 200: return False
        for pat in ERROR_PATTERNS:
            if re.search(pat, text, re.I): return True
        domain = requests.utils.urlparse(url).netloc
        k = (domain, length)
        self.seen_sizes[k] = self.seen_sizes.get(k, 0) + 1
        if self.seen_sizes[k] > 4: return True
        return False

    def is_interesting(self, code, text, url, length, loc):
        if code == 404 or not text.strip(): return False
        if code == 200 and self.is_fake_200(code, text, url, length): return False
        if 300 <= code < 400 and loc:
            netloc = requests.utils.urlparse(url).netloc
            if netloc not in loc: return False
        return True

    def code_color(self, code):
        if code == 200: return "green"
        if code == 403: return "red"
        if 300 <= code < 500: return "yellow"
        if code >= 500: return "magenta"
        return "gray"

    def detect_waf(self, resp):
        for name, pattern in WAFS.items():
            if re.search(pattern, resp.text, re.I) or name in resp.headers.get("Server", "").lower():
                return name
        return None

    def append_result(self, code, url, length, loc, waf, clr):
        msg = f"[{code}] {url} ({length}B)"
        if loc: msg += f" → {loc}"
        if waf: msg += f" (WAF: {waf})"
        signals.log.emit(msg, clr)

    def append_save(self, code, url, length, loc, waf):
        line = f"{code}\t{url}\t{length}B"
        if loc: line += f"\t-> {loc}"
        if waf: line += f"\tWAF:{waf}"
        try:
            with open(self.results_file, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception as e:
            self.append_log(f"Save Error: {e}")

    def append_log(self, msg):
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(f"{time.ctime()} {msg}\n")
        except: pass
        signals.error.emit(msg)

class RexFuzzGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RexFuzz 2025 🚀")
        self.setGeometry(100, 100, 950, 670)
        self.setStyleSheet("""
            QWidget {
                background-color: #181c22;
                color: #e0e0e0;
                font-size: 15px;
            }
            QTextEdit, QLineEdit {
                background-color: #23272e;
                color: #e0e0e0;
                border-radius: 5px;
            }
            QPushButton {
                background-color: #31353c;
                color: #fff;
                border-radius: 6px;
                padding: 8px 12px;
            }
            QPushButton:hover {
                background-color: #444b57;
            }
            QProgressBar {
                border: 2px solid #31353c;
                border-radius: 5px;
                text-align: center;
                background-color: #23272e;
                color: #fff;
            }
            QProgressBar::chunk {
                background-color: #21c45a;
            }
        """)
        self.fuzzer = None
        self.stop_flag = threading.Event()
        self.init_ui()
        self.connect_signals()

    def init_ui(self):
        main = QVBoxLayout()
        form = QVBoxLayout()
        row1 = QHBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://target.com/FUZZ أو https://target.com/admin/FUZZ/config.php")
        row1.addWidget(QLabel("الرابط:"))
        row1.addWidget(self.url_input)
        self.status_lbl = QLabel("...")
        row1.addWidget(self.status_lbl)
        form.addLayout(row1)

        row2 = QHBoxLayout()
        self.wordlist_input = QLineEdit()
        self.wordlist_input.setPlaceholderText("اختر قائمة الكلمات...")
        self.wordlist_btn = QPushButton("تصفح")
        self.wordlist_btn.clicked.connect(self.pick_wordlist)
        row2.addWidget(QLabel("Wordlist:"))
        row2.addWidget(self.wordlist_input)
        row2.addWidget(self.wordlist_btn)
        form.addLayout(row2)

        row3 = QHBoxLayout()
        self.proxy_input = QLineEdit()
        self.proxy_input.setPlaceholderText("مثال: http://127.0.0.1:8080")
        row3.addWidget(QLabel("Proxy:"))
        row3.addWidget(self.proxy_input)
        self.threads_box = QSpinBox()
        self.threads_box.setRange(1, 99)
        self.threads_box.setValue(22)
        row3.addWidget(QLabel("Threads:"))
        row3.addWidget(self.threads_box)
        self.timeout_box = QSpinBox()
        self.timeout_box.setRange(2, 60)
        self.timeout_box.setValue(8)
        row3.addWidget(QLabel("Timeout:"))
        row3.addWidget(self.timeout_box)
        form.addLayout(row3)

        row4 = QHBoxLayout()
        self.ua_input = QComboBox()
        self.ua_input.addItems(UA_LIST)
        self.ua_input.setEditable(True)
        self.filter_200 = QCheckBox("عرض فقط 200/403/500")
        self.filter_200.setChecked(True)
        row4.addWidget(QLabel("User-Agent:"))
        row4.addWidget(self.ua_input)
        row4.addWidget(self.filter_200)
        form.addLayout(row4)

        btns = QHBoxLayout()
        self.start_btn = QPushButton("بدء الفحص 🚀")
        self.stop_btn = QPushButton("إيقاف")
        self.copy_btn = QPushButton("نسخ الكل")
        self.export_btn = QPushButton("تصدير CSV")
        self.start_btn.clicked.connect(self.start_fuzz)
        self.stop_btn.clicked.connect(self.stop_fuzz)
        self.copy_btn.clicked.connect(self.copy_results)
        self.export_btn.clicked.connect(self.export_csv)
        btns.addWidget(self.start_btn)
        btns.addWidget(self.stop_btn)
        btns.addWidget(self.copy_btn)
        btns.addWidget(self.export_btn)
        form.addLayout(btns)

        main.addLayout(form)

        self.progress = QProgressBar()
        main.addWidget(self.progress)

        self.res_box = QTextEdit()
        self.res_box.setReadOnly(True)
        self.res_box.setFont(QFont('Consolas', 13))
        main.addWidget(self.res_box, 6)

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setFont(QFont('Consolas', 11))
        main.addWidget(QLabel("Logs:"))
        main.addWidget(self.log_box, 2)

        self.setLayout(main)

    def connect_signals(self):
        signals.log.connect(self.add_result)
        signals.progress.connect(self.set_progress)
        signals.finished.connect(self.done_fuzz)
        signals.status.connect(self.set_status)
        signals.waf.connect(self.waf_detected)
        signals.save.connect(self.save_results)
        signals.error.connect(self.log_error)

    def pick_wordlist(self):
        fn, _ = QFileDialog.getOpenFileName(self, "اختر ملف Wordlist", "", "Text Files (*.txt)")
        if fn: self.wordlist_input.setText(fn)

    def set_status(self, text):
        self.status_lbl.setText(text)

    def waf_detected(self, name):
        self.status_lbl.setText(f"WAF Detected: {name}")

    def add_result(self, msg, clr):
        code = int(msg.split("]")[0][1:])
        color = "#21c45a" if code == 200 else "#e84141" if code == 403 else "#f5e663" if code >= 500 else "#f5a623" if 300 <= code < 500 else "#aaa"
        self.res_box.setTextColor(QColor(color))
        self.res_box.append(msg)
        self.res_box.moveCursor(QTextCursor.MoveOperation.End)

    def set_progress(self, val):
        self.progress.setValue(val)

    def copy_results(self):
        self.res_box.selectAll()
        self.res_box.copy()

    def export_csv(self):
        fn, _ = QFileDialog.getSaveFileName(self, "Export CSV", "results.csv", "CSV Files (*.csv)")
        if not fn: return
        try:
            lines = self.res_box.toPlainText().splitlines()
            with open(fn, "w", encoding="utf-8") as f:
                f.write("Code,URL,Size,Location,WAF\n")
                for l in lines:
                    code = l.split("]")[0][1:]
                    url = l.split("]")[1].split("(")[0].strip()
                    size = l.split("(")[1].split("B")[0].strip()
                    loc = "→" in l and l.split("→")[1].split()[0] or ""
                    waf = "WAF:" in l and l.split("WAF:")[1] or ""
                    f.write(f"{code},{url},{size},{loc},{waf}\n")
            self.log_box.append(f"CSV Exported: {fn}")
        except Exception as e:
            self.log_box.append(f"Export Error: {e}")

    def save_results(self, _):
        with open("results.txt", "w", encoding="utf-8") as f:
            f.write(self.res_box.toPlainText())

    def log_error(self, msg):
        self.log_box.append(f"[!] {msg}")

    def done_fuzz(self, tm):
        self.start_btn.setDisabled(False)
        self.stop_btn.setDisabled(True)
        self.progress.setValue(0)
        self.status_lbl.setText(f"تم الانتهاء خلال {round(tm,2)} ثانية.")
        self.save_results("")

    def stop_fuzz(self):
        self.stop_flag.set()
        self.start_btn.setDisabled(False)
        self.stop_btn.setDisabled(True)
        self.status_lbl.setText("تم الإيقاف.")

    def start_fuzz(self):
        url = self.url_input.text().strip()
        wordlist_file = self.wordlist_input.text().strip()
        if not url or not wordlist_file or not os.path.isfile(wordlist_file):
            QMessageBox.warning(self, "خطأ", "يرجى إدخال رابط وقائمة كلمات صحيحة.")
            return
        with open(wordlist_file, "r", encoding="utf-8") as f:
            words = [line.strip() for line in f if line.strip()]
        threads = self.threads_box.value()
        timeout = self.timeout_box.value()
        ua = self.ua_input.currentText()
        proxy = self.proxy_input.text().strip()
        filter_codes = [200, 403, 500] if self.filter_200.isChecked() else list(range(200,600))
        self.res_box.clear()
        self.log_box.clear()
        self.progress.setMaximum(len(words))
        self.progress.setValue(0)
        self.stop_flag = threading.Event()
        self.start_btn.setDisabled(True)
        self.stop_btn.setDisabled(False)
        self.status_lbl.setText("جاري الفحص...")
        self.fuzzer = FuzzerThread(
            url, words, threads, timeout, ua, proxy,
            only_good=True, stop_flag=self.stop_flag,
            results_file="results.txt",
            log_file="logs.txt",
            filter_codes=filter_codes
        )
        self.fuzzer.start()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = RexFuzzGUI()
    win.show()
    sys.exit(app.exec())
