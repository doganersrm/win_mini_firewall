from __future__ import annotations
import sys
import ipaddress
import yaml
from dataclasses import dataclass, asdict
from typing import Optional, List

from PySide6 import QtCore, QtGui, QtWidgets
from PySide6.QtCore import Qt

# pydivert (WinDivert wrapper)
try:
    from pydivert import WinDivert, Packet
except Exception as e:
    WinDivert = None  # type: ignore
    Packet = None  # type: ignore

# ---------------------------- Veri Modeli ---------------------------- #
@dataclass
class Rule:
    dir: str = "any"        # in | out | any
    proto: str = "any"      # tcp | udp | icmp | any
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    action: str = "drop"     # accept | drop
    comment: str = ""

@dataclass
class Config:
    default_action: str = "accept"  # accept | drop
    safety_allow_rdp: bool = True
    safety_allow_loopback: bool = True
    rules: List[Rule] = None  # type: ignore

    def to_yaml(self) -> str:
        data = {
            "default_action": self.default_action,
            "safety": {
                "allow_rdp": self.safety_allow_rdp,
                "allow_loopback": self.safety_allow_loopback,
            },
            "rules": [asdict(r) for r in self.rules or []],
        }
        return yaml.safe_dump(data, sort_keys=False, allow_unicode=True)

    @staticmethod
    def from_yaml(text: str) -> "Config":
        loaded = yaml.safe_load(text) or {}
        default_action = (loaded.get("default_action") or "accept").lower()
        safety = loaded.get("safety", {}) or {}
        rules_yaml = loaded.get("rules", []) or []
        rules = []
        for r in rules_yaml:
            rules.append(
                Rule(
                    dir=(r.get("dir") or "any").lower(),
                    proto=(r.get("proto") or "any").lower(),
                    src_ip=r.get("src_ip"),
                    dst_ip=r.get("dst_ip"),
                    src_port=r.get("src_port"),
                    dst_port=r.get("dst_port"),
                    action=(r.get("action") or "drop").lower(),
                    comment=r.get("comment") or "",
                )
            )
        return Config(
            default_action=default_action,
            safety_allow_rdp=bool(safety.get("allow_rdp", True)),
            safety_allow_loopback=bool(safety.get("allow_loopback", True)),
            rules=rules,
        )

# ---------------------------- Qt Tablo Modeli ---------------------------- #
class RuleTableModel(QtCore.QAbstractTableModel):
    HEADERS = [
        "Dir", "Proto", "Src IP", "Dst IP", "Src Port", "Dst Port", "Action", "Comment"
    ]

    def __init__(self, rules: List[Rule] | None = None, parent=None):
        super().__init__(parent)
        self._rules: List[Rule] = rules or []

    def rowCount(self, parent=QtCore.QModelIndex()) -> int:
        return len(self._rules)

    def columnCount(self, parent=QtCore.QModelIndex()) -> int:
        return len(self.HEADERS)

    def data(self, index: QtCore.QModelIndex, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        r = self._rules[index.row()]
        col = index.column()
        if role in (Qt.DisplayRole, Qt.EditRole):
            return [
                r.dir, r.proto, r.src_ip or "", r.dst_ip or "",
                r.src_port if r.src_port is not None else "",
                r.dst_port if r.dst_port is not None else "",
                r.action, r.comment
            ][col]
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            return self.HEADERS[section]
        return section + 1

    def flags(self, index):
        if not index.isValid():
            return Qt.ItemIsEnabled
        return Qt.ItemIsSelectable | Qt.ItemIsEnabled

    # CRUD helpers
    def add_rule(self, rule: Rule):
        self.beginInsertRows(QtCore.QModelIndex(), len(self._rules), len(self._rules))
        self._rules.append(rule)
        self.endInsertRows()

    def remove_rows(self, rows: List[int]):
        for row in sorted(rows, reverse=True):
            self.beginRemoveRows(QtCore.QModelIndex(), row, row)
            self._rules.pop(row)
            self.endRemoveRows()

    def update_rule(self, row: int, rule: Rule):
        if 0 <= row < len(self._rules):
            self._rules[row] = rule
            top_left = self.index(row, 0)
            bottom_right = self.index(row, self.columnCount() - 1)
            self.dataChanged.emit(top_left, bottom_right)

    def rules(self) -> List[Rule]:
        return list(self._rules)

# ---------------------------- Kural Dialogu ---------------------------- #
class RuleDialog(QtWidgets.QDialog):
    def __init__(self, parent=None, rule: Rule | None = None):
        super().__init__(parent)
        self.setWindowTitle("Kural Düzenle")
        self.setModal(True)
        self.setMinimumWidth(460)
        self.rule: Rule | None = None

        dir_cb = QtWidgets.QComboBox(); dir_cb.addItems(["any", "in", "out"])
        proto_cb = QtWidgets.QComboBox(); proto_cb.addItems(["any", "tcp", "udp", "icmp"])
        self.dir_cb = dir_cb; self.proto_cb = proto_cb

        self.src_ip = QtWidgets.QLineEdit(); self.dst_ip = QtWidgets.QLineEdit()
        self.src_port = QtWidgets.QSpinBox(); self.src_port.setRange(0, 65535); self.src_port.setSpecialValueText("")
        self.dst_port = QtWidgets.QSpinBox(); self.dst_port.setRange(0, 65535); self.dst_port.setSpecialValueText("")
        self.src_port.setValue(0); self.dst_port.setValue(0)
        self.action_cb = QtWidgets.QComboBox(); self.action_cb.addItems(["accept", "drop"])
        self.comment = QtWidgets.QLineEdit()

        form = QtWidgets.QFormLayout()
        form.addRow("Yön (dir)", dir_cb)
        form.addRow("Protokol", proto_cb)
        form.addRow("Src IP (CIDR)", self.src_ip)
        form.addRow("Dst IP (CIDR)", self.dst_ip)
        form.addRow("Src Port", self.src_port)
        form.addRow("Dst Port", self.dst_port)
        form.addRow("Aksiyon", self.action_cb)
        form.addRow("Açıklama", self.comment)

        btn_ok = QtWidgets.QPushButton("Kaydet")
        btn_cancel = QtWidgets.QPushButton("Vazgeç")
        btn_ok.clicked.connect(self.accept)
        btn_cancel.clicked.connect(self.reject)
        btn_box = QtWidgets.QHBoxLayout()
        btn_box.addStretch(1)
        btn_box.addWidget(btn_cancel)
        btn_box.addWidget(btn_ok)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addLayout(form)
        layout.addLayout(btn_box)

        if rule:
            self.dir_cb.setCurrentText(rule.dir)
            self.proto_cb.setCurrentText(rule.proto)
            self.src_ip.setText(rule.src_ip or "")
            self.dst_ip.setText(rule.dst_ip or "")
            self.src_port.setValue(rule.src_port if rule.src_port is not None else 0)
            self.dst_port.setValue(rule.dst_port if rule.dst_port is not None else 0)
            self.action_cb.setCurrentText(rule.action)
            self.comment.setText(rule.comment)

    def accept(self):
        # Basit doğrulama
        def chk_ip(txt: str) -> Optional[str]:
            t = txt.strip()
            if not t:
                return None
            try:
                # Hem tek IP hem CIDR destekle
                if "/" in t:
                    ipaddress.ip_network(t, strict=False)
                else:
                    ipaddress.ip_address(t)
                return t
            except Exception:
                QtWidgets.QMessageBox.warning(self, "Hata", f"Geçersiz IP/CIDR: {t}")
                return None

        s_ip = chk_ip(self.src_ip.text()) if self.src_ip.text().strip() else None
        if self.src_ip.text().strip() and s_ip is None:
            return
        d_ip = chk_ip(self.dst_ip.text()) if self.dst_ip.text().strip() else None
        if self.dst_ip.text().strip() and d_ip is None:
            return

        s_port = self.src_port.value() or None
        d_port = self.dst_port.value() or None
        self.rule = Rule(
            dir=self.dir_cb.currentText(),
            proto=self.proto_cb.currentText(),
            src_ip=s_ip,
            dst_ip=d_ip,
            src_port=s_port,
            dst_port=d_port,
            action=self.action_cb.currentText(),
            comment=self.comment.text().strip(),
        )
        super().accept()

# ---------------------------- Firewall Thread ---------------------------- #
class FirewallThread(QtCore.QThread):
    statsChanged = QtCore.Signal(int, int)  # accepted, dropped
    status = QtCore.Signal(str)

    def __init__(self, cfg: Config, parent=None):
        super().__init__(parent)
        self.cfg = cfg
        self._running = True
        self.accepted = 0
        self.dropped = 0

    # ---- Karar Mekanizması ---- #
    def _ip_match(self, rule_val: Optional[str], val: str) -> bool:
        if not rule_val or rule_val == "any":
            return True
        try:
            return ipaddress.ip_address(val) in ipaddress.ip_network(rule_val, strict=False)
        except Exception:
            return False

    def _proto_of(self, pkt: Packet) -> str:
        if pkt.tcp is not None: return "tcp"
        if pkt.udp is not None: return "udp"
        if (getattr(pkt, "icmpv4", None) is not None) or (getattr(pkt, "icmpv6", None) is not None) or (getattr(pkt, "icmp", None) is not None): return "icmp"
        return "any"

    def _dir_of(self, pkt: Packet) -> str:
        return "in" if pkt.is_inbound else "out"

    def _port_of(self, pkt: Packet, which: str) -> Optional[int]:
        if pkt.tcp is not None:
            return pkt.tcp.src_port if which == "sport" else pkt.tcp.dst_port
        if pkt.udp is not None:
            return pkt.udp.src_port if which == "sport" else pkt.udp.dst_port
        return None

    def _is_safety_allow(self, pkt: Packet) -> bool:
        # RDP
        if self.cfg.safety_allow_rdp and pkt.tcp is not None:
            if pkt.tcp.src_port == 3389 or pkt.tcp.dst_port == 3389:
                return True
        # Loopback
        if self.cfg.safety_allow_loopback:
            try:
                if ipaddress.ip_address(pkt.src_addr) in ipaddress.ip_network("127.0.0.0/8"):
                    return True
                if ipaddress.ip_address(pkt.dst_addr) in ipaddress.ip_network("127.0.0.0/8"):
                    return True
            except Exception:
                pass
            if pkt.src_addr == "::1" or pkt.dst_addr == "::1":
                return True
        return False

    def decide(self, pkt: Packet) -> str:
        if self._is_safety_allow(pkt):
            return "accept"

        pdir = self._dir_of(pkt)
        pproto = self._proto_of(pkt)
        for r in self.cfg.rules or []:
            if r.dir != "any" and r.dir != pdir:
                continue
            if r.proto != "any" and r.proto != pproto:
                continue
            if not self._ip_match(r.src_ip, pkt.src_addr):
                continue
            if not self._ip_match(r.dst_ip, pkt.dst_addr):
                continue
            if r.src_port is not None:
                sp = self._port_of(pkt, "sport")
                if sp != r.src_port:
                    continue
            if r.dst_port is not None:
                dp = self._port_of(pkt, "dport")
                if dp != r.dst_port:
                    continue
            return r.action
        return self.cfg.default_action

    def run(self):
        if WinDivert is None:
            self.status.emit("pydivert yüklenemedi. 'pip install pydivert'?")
            return
        flt = "(ip || ipv6) && (tcp || udp || icmp || icmpv6)"
        self.status.emit("WinDivert açılıyor… (Yönetici yetkisi şart)")
        try:
            with WinDivert(flt, priority=300) as w:
                self.status.emit("Filtre aktif")
                while self._running:
                    try:
                        pkt = w.recv()
                    except Exception:
                        continue
                    action = self.decide(pkt)
                    if action == "accept":
                        try:
                            w.send(pkt)
                        except Exception:
                            pass
                        self.accepted += 1
                    else:
                        # drop: yeniden enjekte etme
                        self.dropped += 1
                    if (self.accepted + self.dropped) % 50 == 0:
                        self.statsChanged.emit(self.accepted, self.dropped)
            self.status.emit("Filtre kapandı")
        except PermissionError:
            self.status.emit("Yönetici izni yok. PowerShell'i Yönetici olarak açın.")
        except Exception as e:
            self.status.emit(f"Hata: {e}")

    def stop(self):
        self._running = False

# ---------------------------- Ana Pencere ---------------------------- #
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WinMiniFirewall GUI")
        self.resize(980, 560)
        self._cfg = Config(default_action="accept", rules=[])
        self._fw_thread: FirewallThread | None = None

        # Üst bar: varsayılan aksiyon + güvenlik istisnaları
        top = QtWidgets.QWidget()
        top_l = QtWidgets.QHBoxLayout(top)
        self.default_cb = QtWidgets.QComboBox(); self.default_cb.addItems(["accept", "drop"])
        top_l.addWidget(QtWidgets.QLabel("Varsayılan eylem:"))
        top_l.addWidget(self.default_cb)
        self.chk_rdp = QtWidgets.QCheckBox("RDP'yi her zaman izin ver (3389)")
        self.chk_loop = QtWidgets.QCheckBox("Loopback'e her zaman izin ver (127.0.0.0/8, ::1)")
        self.chk_rdp.setChecked(True); self.chk_loop.setChecked(True)
        top_l.addSpacing(12)
        top_l.addWidget(self.chk_rdp); top_l.addWidget(self.chk_loop)
        top_l.addStretch(1)

        # Orta: tablo + butonlar
        self.model = RuleTableModel([])
        self.table = QtWidgets.QTableView()
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)

        btn_add = QtWidgets.QPushButton("Yeni")
        btn_edit = QtWidgets.QPushButton("Düzenle")
        btn_del = QtWidgets.QPushButton("Sil")
        btn_load = QtWidgets.QPushButton("Aç…")
        btn_save = QtWidgets.QPushButton("Kaydet…")
        btn_start = QtWidgets.QPushButton("Başlat")
        btn_stop = QtWidgets.QPushButton("Durdur")

        btns = QtWidgets.QVBoxLayout()
        for b in (btn_add, btn_edit, btn_del, btn_load, btn_save, btn_start, btn_stop):
            btns.addWidget(b)
        btns.addStretch(1)

        center = QtWidgets.QWidget()
        c_l = QtWidgets.QHBoxLayout(center)
        c_l.addWidget(self.table, 1)
        c_l.addLayout(btns)

        # Alt: durum çizgisi
        self.status_label = QtWidgets.QLabel("Hazır")
        self.stats_label = QtWidgets.QLabel("0 accept / 0 drop")
        bottom = QtWidgets.QWidget()
        b_l = QtWidgets.QHBoxLayout(bottom)
        b_l.addWidget(self.status_label)
        b_l.addStretch(1)
        b_l.addWidget(self.stats_label)

        # Merkez düzen
        wrapper = QtWidgets.QWidget()
        v = QtWidgets.QVBoxLayout(wrapper)
        v.addWidget(top)
        v.addWidget(center, 1)
        v.addWidget(bottom)
        self.setCentralWidget(wrapper)

        # Sinyaller
        btn_add.clicked.connect(self.on_add)
        btn_edit.clicked.connect(self.on_edit)
        btn_del.clicked.connect(self.on_del)
        btn_load.clicked.connect(self.on_load)
        btn_save.clicked.connect(self.on_save)
        btn_start.clicked.connect(self.on_start)
        btn_stop.clicked.connect(self.on_stop)

    # ---------- Helpers ---------- #
    def current_cfg(self) -> Config:
        return Config(
            default_action=self.default_cb.currentText(),
            safety_allow_rdp=self.chk_rdp.isChecked(),
            safety_allow_loopback=self.chk_loop.isChecked(),
            rules=self.model.rules(),
        )

    def apply_cfg_to_ui(self, cfg: Config):
        self._cfg = cfg
        self.default_cb.setCurrentText(cfg.default_action)
        self.chk_rdp.setChecked(cfg.safety_allow_rdp)
        self.chk_loop.setChecked(cfg.safety_allow_loopback)
        self.model = RuleTableModel(cfg.rules or [])
        self.table.setModel(self.model)
        self.table.resizeColumnsToContents()

    # ---------- CRUD ---------- #
    def on_add(self):
        dlg = RuleDialog(self)
        if dlg.exec() == QtWidgets.QDialog.Accepted and dlg.rule:
            self.model.add_rule(dlg.rule)

    def _selected_rows(self) -> List[int]:
        rows = sorted(set(i.row() for i in self.table.selectionModel().selectedRows()))
        return rows

    def on_edit(self):
        rows = self._selected_rows()
        if len(rows) != 1:
            QtWidgets.QMessageBox.information(self, "Bilgi", "Düzenlemek için tek bir satır seçin.")
            return
        row = rows[0]
        rule = self.model.rules()[row]
        dlg = RuleDialog(self, rule)
        if dlg.exec() == QtWidgets.QDialog.Accepted and dlg.rule:
            self.model.update_rule(row, dlg.rule)

    def on_del(self):
        rows = self._selected_rows()
        if not rows:
            return
        if QtWidgets.QMessageBox.question(self, "Sil", f"{len(rows)} kural silinsin mi?") == QtWidgets.QMessageBox.Yes:
            self.model.remove_rows(rows)

    # ---------- IO ---------- #
    def on_load(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Kural dosyası aç", "", "YAML Files (*.yml *.yaml)")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                text = f.read()
            cfg = Config.from_yaml(text)
            self.apply_cfg_to_ui(cfg)
            self.status_label.setText(f"Yüklendi: {path}")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Hata", f"Açılamadı: {e}")

    def on_save(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Kural dosyası kaydet", "rules.yaml", "YAML Files (*.yml *.yaml)")
        if not path:
            return
        try:
            cfg = self.current_cfg()
            with open(path, "w", encoding="utf-8") as f:
                f.write(cfg.to_yaml())
            self.status_label.setText(f"Kaydedildi: {path}")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Hata", f"Kaydedilemedi: {e}")

    # ---------- Firewall kontrol ---------- #
    def on_start(self):
        if self._fw_thread and self._fw_thread.isRunning():
            QtWidgets.QMessageBox.information(self, "Bilgi", "Zaten çalışıyor.")
            return
        cfg = self.current_cfg()
        self._fw_thread = FirewallThread(cfg)
        self._fw_thread.statsChanged.connect(self.on_stats)
        self._fw_thread.status.connect(self.on_status)
        self._fw_thread.start()
        self.status_label.setText("Çalışıyor…")

    def on_stop(self):
        if self._fw_thread and self._fw_thread.isRunning():
            self._fw_thread.stop()
            self._fw_thread.wait(1500)
            self._fw_thread = None
            self.status_label.setText("Durduruldu")

    @QtCore.Slot(int, int)
    def on_stats(self, acc: int, drp: int):
        self.stats_label.setText(f"{acc} accept / {drp} drop")

    @QtCore.Slot(str)
    def on_status(self, msg: str):
        self.status_label.setText(msg)

# ---------------------------- main ---------------------------- #
def main():
    app = QtWidgets.QApplication(sys.argv)
    # Basit koyu tema
    app.setStyle("Fusion")
    pal = app.palette()
    pal.setColor(QtGui.QPalette.Window, QtGui.QColor(30, 30, 30))
    pal.setColor(QtGui.QPalette.WindowText, Qt.white)
    pal.setColor(QtGui.QPalette.Base, QtGui.QColor(22, 22, 22))
    pal.setColor(QtGui.QPalette.AlternateBase, QtGui.QColor(35, 35, 35))
    pal.setColor(QtGui.QPalette.ToolTipBase, Qt.white)
    pal.setColor(QtGui.QPalette.ToolTipText, Qt.white)
    pal.setColor(QtGui.QPalette.Text, Qt.white)
    pal.setColor(QtGui.QPalette.Button, QtGui.QColor(45, 45, 45))
    pal.setColor(QtGui.QPalette.ButtonText, Qt.white)
    pal.setColor(QtGui.QPalette.Highlight, QtGui.QColor(53, 132, 228))
    pal.setColor(QtGui.QPalette.HighlightedText, Qt.black)
    app.setPalette(pal)

    w = MainWindow()
    w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    if not hasattr(sys, "getwindowsversion"):
        print("Uyarı: Bu GUI Windows için tasarlandı.")
    main()
