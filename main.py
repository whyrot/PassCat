import sys, os, hashlib, base64, random, string
from cryptography.fernet import Fernet
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QLineEdit, QDialog, QFormLayout, QDialogButtonBox, QTextEdit, QSpinBox, QMessageBox
)
from PyQt6.QtGui import QFont, QPixmap
from PyQt6.QtCore import Qt

KEY_FILE = 'key.key'
PASS_FILE = 'passwords.txt'
MASTER_FILE = 'master.txt'

def create_master_password_gui():
    dlg = QDialog()
    dlg.setWindowTitle("Set Master Password")
    dlg.setStyleSheet("background-color: #2b2b2b; color: white;")
    layout = QFormLayout()
    master_input = QLineEdit()
    master_input.setEchoMode(QLineEdit.EchoMode.Password)
    layout.addRow("Set Master Password:", master_input)
    buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
    buttons.accepted.connect(dlg.accept)
    buttons.rejected.connect(dlg.reject)
    layout.addWidget(buttons)
    dlg.setLayout(layout)
    if dlg.exec():
        master_pass = master_input.text()
        if not master_pass:
            return create_master_password_gui()
        hashed = hashlib.sha256(master_pass.encode()).hexdigest()
        with open(MASTER_FILE, 'w') as f:
            f.write(hashed)
        key = Fernet.generate_key()
        cipher = Fernet(base64.urlsafe_b64encode(hashlib.sha256(master_pass.encode()).digest()))
        encrypted_key = cipher.encrypt(key)
        with open(KEY_FILE, 'wb') as f:
            f.write(encrypted_key)
        with open(PASS_FILE, "w") as f:
            pass
        sys.exit()

def verify_master_password_gui():
    dlg = QDialog()
    dlg.setWindowTitle("Enter Master Password")
    dlg.setStyleSheet("background-color: #2b2b2b; color: white;")
    layout = QFormLayout()
    master_input = QLineEdit()
    master_input.setEchoMode(QLineEdit.EchoMode.Password)
    layout.addRow("Master Password:", master_input)
    buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
    buttons.accepted.connect(dlg.accept)
    buttons.rejected.connect(dlg.reject)
    layout.addWidget(buttons)
    dlg.setLayout(layout)
    if dlg.exec():
        master_pass = master_input.text()
        if not master_pass:
            return verify_master_password_gui()
        hashed = hashlib.sha256(master_pass.encode()).hexdigest()
        with open(MASTER_FILE, 'r') as f:
            stored_hash = f.read()
        if hashed != stored_hash:
            return verify_master_password_gui()
        cipher = Fernet(base64.urlsafe_b64encode(hashlib.sha256(master_pass.encode()).digest()))
        with open(KEY_FILE, 'rb') as f:
            key = cipher.decrypt(f.read())
        return Fernet(key)
    else:
        sys.exit()

class PasswordManager(QMainWindow):
    def __init__(self, fernet):
        super().__init__()
        self.fernet = fernet
        self.setWindowTitle("PassCat")
        self.resize(600, 400)

        central = QWidget()
        central.setStyleSheet("background-color: #2b2b2b; color: white;")
        main_layout = QVBoxLayout()

        logo_layout = QHBoxLayout()
        logo_label = QLabel()
        pixmap = QPixmap("logo.png").scaled(50, 50, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
        logo_label.setPixmap(pixmap)
        logo_label.setFixedSize(50, 50)
        logo_layout.addWidget(logo_label, alignment=Qt.AlignmentFlag.AlignLeft)
        logo_layout.addStretch()
        main_layout.addLayout(logo_layout)

        title = QLabel("PassCat")
        title.setFont(QFont("Verdana", 20, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(title)
        main_layout.addSpacing(20)

        btn_style = """
            QPushButton {
                background-color: #444;
                color: white;
                border-radius: 12px;
                padding: 10px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #666;
            }
        """

        add_btn = QPushButton("Add Password")
        add_btn.setStyleSheet(btn_style)
        add_btn.clicked.connect(self.add_password)
        view_btn = QPushButton("View Passwords")
        view_btn.setStyleSheet(btn_style)
        view_btn.clicked.connect(self.view_passwords)
        gen_btn = QPushButton("Generate Password")
        gen_btn.setStyleSheet(btn_style)
        gen_btn.clicked.connect(self.generate_password)
        clear_btn = QPushButton("Clear All Passwords")
        clear_btn.setStyleSheet(btn_style)
        clear_btn.clicked.connect(self.clear_passwords)
        delete_master_btn = QPushButton("Delete Master Password and Key")
        delete_master_btn.setStyleSheet(btn_style)
        delete_master_btn.clicked.connect(self.delete_master_key)

        main_layout.addWidget(add_btn)
        main_layout.addWidget(view_btn)
        main_layout.addWidget(gen_btn)
        main_layout.addWidget(clear_btn)
        main_layout.addWidget(delete_master_btn)

        central.setLayout(main_layout)
        self.setCentralWidget(central)

    def add_password(self):
        dlg = QDialog()
        dlg.setWindowTitle("Add Password")
        dlg.setStyleSheet("background-color: #2b2b2b; color: white;")
        layout = QFormLayout()
        platform_input = QLineEdit()
        email_input = QLineEdit()
        password_input = QLineEdit()
        password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addRow("Platform:", platform_input)
        layout.addRow("Email/Username:", email_input)
        layout.addRow("Password:", password_input)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        layout.addWidget(buttons)
        dlg.setLayout(layout)
        if dlg.exec():
            platform = platform_input.text()
            email = email_input.text()
            pw = password_input.text()
            if not platform or not email or not pw:
                QMessageBox.warning(self, "PassCat", "All fields are required.")
                return
            encrypted_pw = self.fernet.encrypt(pw.encode())
            with open(PASS_FILE, "a") as f:
                f.write(f"{platform}|{email}|{encrypted_pw.decode()}\n")

    def view_passwords(self):
        dlg = QDialog()
        dlg.setWindowTitle("Stored Passwords")
        dlg.setStyleSheet("background-color: #2b2b2b; color: white;")
        layout = QVBoxLayout()
        text = QTextEdit()
        text.setReadOnly(True)
        if not os.path.exists(PASS_FILE) or os.path.getsize(PASS_FILE) == 0:
            text.setPlainText("No passwords stored.")
        else:
            with open(PASS_FILE, "r") as f:
                lines = f.readlines()
            result = []
            for line in lines:
                try:
                    platform, email, encrypted_pw = line.strip().split("|")
                    decrypted_pw = self.fernet.decrypt(encrypted_pw.encode()).decode()
                    result.append(f"Platform: {platform}\nEmail: {email}\nPassword: {decrypted_pw}\n")
                except:
                    pass
            text.setPlainText("\n".join(result))
        layout.addWidget(text)
        dlg.setLayout(layout)
        dlg.exec()

    def generate_password(self):
        dlg = QDialog()
        dlg.setWindowTitle("Password Generator")
        dlg.setStyleSheet("background-color: #2b2b2b; color: white;")
        layout = QFormLayout()
        length_spin = QSpinBox()
        length_spin.setRange(6, 64)
        length_spin.setValue(12)
        output = QLineEdit()
        output.setReadOnly(True)
        generate_btn = QPushButton("Generate")
        def gen():
            length = length_spin.value()
            disallowed = set(["'", '"', '\\', '`', '<', '>', '/', '-', '_'])
            punctuation = string.punctuation
            allowed_punctuation = ''.join(ch for ch in punctuation if ch not in disallowed)
            characters = string.ascii_letters + string.digits + allowed_punctuation
            securepass = ''.join(random.choice(characters) for _ in range(length))
            output.setText(securepass)
        generate_btn.clicked.connect(gen)
        layout.addRow("Length:", length_spin)
        layout.addRow(generate_btn)
        layout.addRow("Generated:", output)
        dlg.setLayout(layout)
        dlg.exec()

    def clear_passwords(self):
        confirm = QMessageBox.question(self, "PassCat", "Are you sure you want to clear ALL passwords?",
                                       QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if confirm == QMessageBox.StandardButton.Yes:
            with open(PASS_FILE, "w") as f:
                pass

    def delete_master_key(self):
        confirm = QMessageBox.question(self, "PassCat",
                                       "This will delete your master password and encryption key. You will lose access to all passwords. Continue?",
                                       QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if confirm == QMessageBox.StandardButton.Yes:
            if os.path.exists(MASTER_FILE):
                os.remove(MASTER_FILE)
            if os.path.exists(KEY_FILE):
                os.remove(KEY_FILE)
            QMessageBox.information(self, "PassCat", "Master password and key deleted. Restart program.")
            sys.exit()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setFont(QFont("Verdana", 10))
    if not os.path.exists(MASTER_FILE) or os.path.getsize(MASTER_FILE) == 0:
        create_master_password_gui()
    fernet = verify_master_password_gui()
    win = PasswordManager(fernet)
    win.show()
    sys.exit(app.exec())
