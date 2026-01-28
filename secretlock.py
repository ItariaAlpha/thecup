import base64
import json
import os
import sys
import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
except ImportError:  # pragma: no cover - optional dependency
    DND_FILES = None
    TkinterDnD = None

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MASTER_PHRASE = "itaria277"
META_FILENAME = ".secretlock_meta.json"
ENCRYPTED_SUFFIX = ".slk"
PBKDF2_ITERATIONS = 200_000
KEY_LENGTH = 32
NONCE_LENGTH = 12


@dataclass
class EncryptedKey:
    nonce: str
    ciphertext: str


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def _wrap_data_key(data_key: bytes, password: str, salt: bytes) -> EncryptedKey:
    key = _derive_key(password, salt)
    aes = AESGCM(key)
    nonce = os.urandom(NONCE_LENGTH)
    ciphertext = aes.encrypt(nonce, data_key, b"secretlock-key")
    return EncryptedKey(
        nonce=base64.b64encode(nonce).decode("utf-8"),
        ciphertext=base64.b64encode(ciphertext).decode("utf-8"),
    )


def _unwrap_data_key(enc_key: EncryptedKey, password: str, salt: bytes) -> bytes:
    key = _derive_key(password, salt)
    aes = AESGCM(key)
    nonce = base64.b64decode(enc_key.nonce)
    ciphertext = base64.b64decode(enc_key.ciphertext)
    return aes.decrypt(nonce, ciphertext, b"secretlock-key")


def _encrypt_file(data_key: bytes, file_path: Path) -> Path:
    aes = AESGCM(data_key)
    nonce = os.urandom(NONCE_LENGTH)
    plaintext = file_path.read_bytes()
    ciphertext = aes.encrypt(nonce, plaintext, file_path.name.encode("utf-8"))
    encrypted_path = file_path.with_name(file_path.name + ENCRYPTED_SUFFIX)
    encrypted_path.write_bytes(nonce + ciphertext)
    file_path.unlink()
    return encrypted_path


def _decrypt_file(data_key: bytes, encrypted_path: Path, original_name: str) -> Path:
    raw = encrypted_path.read_bytes()
    nonce = raw[:NONCE_LENGTH]
    ciphertext = raw[NONCE_LENGTH:]
    aes = AESGCM(data_key)
    plaintext = aes.decrypt(nonce, ciphertext, original_name.encode("utf-8"))
    output_path = encrypted_path.with_name(original_name)
    output_path.write_bytes(plaintext)
    encrypted_path.unlink()
    return output_path


def _load_meta(folder: Path) -> dict:
    meta_path = folder / META_FILENAME
    if not meta_path.exists():
        return {}
    return json.loads(meta_path.read_text(encoding="utf-8"))


def _save_meta(folder: Path, data: dict) -> None:
    meta_path = folder / META_FILENAME
    meta_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _list_top_level_files(folder: Path) -> list[Path]:
    return [
        item
        for item in folder.iterdir()
        if item.is_file()
        and item.name != META_FILENAME
        and not item.name.endswith(ENCRYPTED_SUFFIX)
    ]


def _open_folder(folder: Path) -> None:
    if sys.platform.startswith("win"):
        os.startfile(folder)  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        os.system(f'open "{folder}"')
    else:
        os.system(f'xdg-open "{folder}"')


BaseTk = TkinterDnD.Tk if TkinterDnD else tk.Tk


class SecretLockApp(BaseTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("SecretLock 文件夹加密工具")
        self.geometry("520x360")
        self.resizable(False, False)
        self.selected_folder: Path | None = None
        self._setup_ui()
        self._setup_drag_and_drop()

    def _setup_ui(self) -> None:
        self.configure(padx=16, pady=16)

        title = ttk.Label(
            self,
            text="SecretLock - 顶层文件加密",
            font=("Arial", 16, "bold"),
        )
        title.pack(anchor="center", pady=(0, 12))

        desc = ttk.Label(
            self,
            text="提示：仅加密选中文件夹顶层文件，不包含子文件夹。",
            wraplength=480,
        )
        desc.pack(anchor="center", pady=(0, 12))

        self.folder_label = ttk.Label(self, text="尚未选择文件夹")
        self.folder_label.pack(anchor="center", pady=(0, 10))

        select_button = ttk.Button(self, text="选择文件夹", command=self._select_folder)
        select_button.pack(anchor="center", pady=(0, 10))

        password_frame = ttk.Frame(self)
        password_frame.pack(fill="x", pady=(0, 12))

        ttk.Label(password_frame, text="密码：").pack(side="left")
        self.password_entry = ttk.Entry(password_frame, show="*")
        self.password_entry.pack(side="left", fill="x", expand=True)

        button_frame = ttk.Frame(self)
        button_frame.pack(fill="x", pady=(0, 12))

        encrypt_btn = ttk.Button(button_frame, text="加密文件夹", command=self._encrypt_folder)
        encrypt_btn.pack(side="left", expand=True, fill="x", padx=4)

        decrypt_btn = ttk.Button(button_frame, text="解密并打开", command=self._decrypt_folder)
        decrypt_btn.pack(side="left", expand=True, fill="x", padx=4)

        forgot_btn = ttk.Button(self, text="忘记密码", command=self._forgot_password)
        forgot_btn.pack(fill="x")

        footer = ttk.Label(
            self,
            text="权限声明：保留最高修改与解析权限，并保留后续优化修改与功能添加的权利。",
            wraplength=480,
        )
        footer.pack(anchor="center", pady=(12, 0))

    def _setup_drag_and_drop(self) -> None:
        if not DND_FILES:
            return

        if not hasattr(self, "drop_target_register"):
            return

        self.drop_target_register(DND_FILES)
        self.dnd_bind("<<Drop>>", self._on_drop)

    def _on_drop(self, event: tk.Event) -> None:
        data = event.data.strip()
        if data.startswith("{") and data.endswith("}"):
            data = data[1:-1]
        folder = Path(data)
        if folder.exists() and folder.is_dir():
            self._set_folder(folder)
        else:
            messagebox.showerror("错误", "请拖入有效的文件夹。")

    def _select_folder(self) -> None:
        folder = filedialog.askdirectory()
        if folder:
            self._set_folder(Path(folder))

    def _set_folder(self, folder: Path) -> None:
        self.selected_folder = folder
        self.folder_label.config(text=f"当前文件夹：{folder}")

    def _encrypt_folder(self) -> None:
        folder = self._require_folder()
        if not folder:
            return

        if (folder / META_FILENAME).exists():
            messagebox.showwarning("提示", "该文件夹已加密。若需撤回，请使用解密功能。")
            return

        password = self.password_entry.get().strip()
        if not password:
            messagebox.showwarning("提示", "请先输入密码。")
            return

        files = _list_top_level_files(folder)
        if not files:
            messagebox.showwarning("提示", "该文件夹没有可加密的顶层文件。")
            return

        data_key = os.urandom(KEY_LENGTH)
        salt = os.urandom(16)
        enc_key_password = _wrap_data_key(data_key, password, salt)
        enc_key_master = _wrap_data_key(data_key, MASTER_PHRASE, salt)

        encrypted_entries = []
        for file_path in files:
            encrypted_path = _encrypt_file(data_key, file_path)
            encrypted_entries.append(
                {"original": file_path.name, "encrypted": encrypted_path.name}
            )

        meta = {
            "version": 1,
            "salt": base64.b64encode(salt).decode("utf-8"),
            "iterations": PBKDF2_ITERATIONS,
            "key_password": enc_key_password.__dict__,
            "key_master": enc_key_master.__dict__,
            "files": encrypted_entries,
        }
        _save_meta(folder, meta)
        messagebox.showinfo("完成", "加密完成。")

    def _decrypt_folder(self) -> None:
        folder = self._require_folder()
        if not folder:
            return

        meta = _load_meta(folder)
        if not meta:
            messagebox.showwarning("提示", "该文件夹未加密。")
            return

        password = self.password_entry.get().strip()
        if not password:
            messagebox.showwarning("提示", "请输入密码。")
            return

        try:
            data_key = self._get_data_key(meta, password, use_master=False)
        except Exception:
            messagebox.showerror("错误", "密码不正确，无法解密。")
            return

        self._restore_files(folder, meta, data_key)
        messagebox.showinfo("完成", "解密完成，正在打开文件夹。")
        _open_folder(folder)

    def _forgot_password(self) -> None:
        folder = self._require_folder()
        if not folder:
            return

        meta = _load_meta(folder)
        if not meta:
            messagebox.showwarning("提示", "该文件夹未加密。")
            return

        master = simpledialog.askstring("忘记密码", "请输入权限词：", show="*")
        if not master:
            return
        if master.strip() != MASTER_PHRASE:
            messagebox.showerror("错误", "权限词错误。")
            return

        try:
            data_key = self._get_data_key(meta, MASTER_PHRASE, use_master=True)
        except Exception:
            messagebox.showerror("错误", "无法使用权限词解密。")
            return

        self._restore_files(folder, meta, data_key)
        messagebox.showinfo("完成", "已解除密码并解密，正在打开文件夹。")
        _open_folder(folder)

    def _get_data_key(self, meta: dict, password: str, use_master: bool) -> bytes:
        salt = base64.b64decode(meta["salt"])
        key_field = "key_master" if use_master else "key_password"
        enc_key_data = meta[key_field]
        enc_key = EncryptedKey(**enc_key_data)
        return _unwrap_data_key(enc_key, password, salt)

    def _restore_files(self, folder: Path, meta: dict, data_key: bytes) -> None:
        entries = meta.get("files", [])
        for entry in entries:
            encrypted_name = entry["encrypted"]
            original_name = entry["original"]
            encrypted_path = folder / encrypted_name
            if encrypted_path.exists():
                _decrypt_file(data_key, encrypted_path, original_name)
        (folder / META_FILENAME).unlink(missing_ok=True)

    def _require_folder(self) -> Path | None:
        if not self.selected_folder:
            messagebox.showwarning("提示", "请先选择或拖入文件夹。")
            return None
        if not self.selected_folder.exists():
            messagebox.showwarning("提示", "文件夹不存在，请重新选择。")
            return None
        return self.selected_folder


if __name__ == "__main__":
    app = SecretLockApp()
    app.mainloop()
