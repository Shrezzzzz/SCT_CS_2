"""
Image Encryption Tool
=====================
Two-panel GUI — Encrypt (left) | Decrypt (right)

Run with:  python main.py
"""

import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import os
import base64
import hashlib
import random
import struct

import numpy as np
from PIL import Image, ImageTk


# ══════════════════════════════════════════════════════════
#  CORE ENCRYPTION / DECRYPTION LOGIC
# ══════════════════════════════════════════════════════════

def _derive_key(passkey: str) -> int:
    return int(hashlib.sha256(passkey.encode()).hexdigest(), 16) % (2 ** 32)


def _shuffle_indices(total: int, seed: int) -> list:
    idx = list(range(total))
    random.seed(seed)
    random.shuffle(idx)
    return idx


def encrypt_image(img: Image.Image, passkey: str) -> bytes:
    """
    Encrypt a PIL image → raw bytes.
    Header: [4B width][4B height][4B mode_len][mode bytes]
    Body:   XOR'd + shuffled pixel data
    """
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGB")

    w, h   = img.size
    mode_b = img.mode.encode()
    pixels = np.array(img, dtype=np.uint8)
    seed   = _derive_key(passkey)

    xored    = (pixels ^ (seed % 256)).astype(np.uint8)
    flat     = xored.reshape(-1, pixels.shape[2])
    shuffled = flat[_shuffle_indices(len(flat), seed)].flatten()

    return struct.pack(">III", w, h, len(mode_b)) + mode_b + shuffled.tobytes()


def decrypt_bytes(enc: bytes, passkey: str) -> Image.Image:
    """Decrypt raw encrypted bytes → PIL image."""
    w, h, mode_len = struct.unpack(">III", enc[:12])
    mode  = enc[12: 12 + mode_len].decode()
    body  = enc[12 + mode_len:]

    channels = len(mode)
    seed     = _derive_key(passkey)

    flat_enc = np.frombuffer(body, dtype=np.uint8).reshape(w * h, channels)
    indices  = _shuffle_indices(w * h, seed)

    restored = np.empty_like(flat_enc)
    for orig, shuf in enumerate(indices):
        restored[orig] = flat_enc[shuf]

    pixels = (restored ^ (seed % 256)).astype(np.uint8).reshape(h, w, channels)
    return Image.fromarray(pixels, mode)


# ══════════════════════════════════════════════════════════
#  THEME
# ══════════════════════════════════════════════════════════

BG      = "#f5f5f5"
WHITE   = "#ffffff"
BORDER  = "#dddddd"
TEXT    = "#222222"
SUBTEXT = "#888888"
ORANGE  = "#e8620a"
ORANGE_H= "#ff7a1f"
INFO_BG = "#e8f4fd"
INFO_FG = "#1a6ea8"
WARN_BG = "#fff9e6"
WARN_FG = "#7a6000"
HEADING = "#111111"
THUMB_W = 340
THUMB_H = 200


def _card(parent):
    return tk.Frame(parent, bg=WHITE,
                    highlightbackground=BORDER, highlightthickness=1)


def _lbl(parent, text, size=10, bold=False, fg=TEXT, **kw):
    return tk.Label(parent, text=text, bg=parent["bg"], fg=fg,
                    font=("Helvetica", size, "bold" if bold else "normal"), **kw)


def _orange_btn(parent, text, cmd, width=12):
    b = tk.Button(parent, text=text, command=cmd,
                  bg=ORANGE, fg="white", activebackground=ORANGE_H,
                  activeforeground="white", relief="flat", bd=0,
                  font=("Helvetica", 10, "bold"),
                  padx=14, pady=7, width=width)
    b.bind("<Enter>", lambda e: b.config(bg=ORANGE_H))
    b.bind("<Leave>", lambda e: b.config(bg=ORANGE))
    return b


def _outline_btn(parent, text, cmd, width=12):
    return tk.Button(parent, text=text, command=cmd,
                     bg=WHITE, fg=TEXT, activebackground="#eeeeee",
                     activeforeground=TEXT, relief="solid", bd=1,
                     font=("Helvetica", 10),
                     padx=14, pady=7, width=width)


def _info_box(parent, text):
    f = tk.Frame(parent, bg=INFO_BG,
                 highlightbackground="#a8d4f0", highlightthickness=1)
    tk.Label(f, text=text, bg=INFO_BG, fg=INFO_FG,
             font=("Helvetica", 9), wraplength=320,
             justify="left", padx=10, pady=8).pack()
    return f


def _warn_box(parent, text):
    f = tk.Frame(parent, bg=WARN_BG,
                 highlightbackground="#e0c96e", highlightthickness=1)
    tk.Label(f, text=text, bg=WARN_BG, fg=WARN_FG,
             font=("Helvetica", 9), wraplength=320,
             justify="left", padx=10, pady=8).pack()
    return f


# ── Passkey widget (handles placeholder internally) ──────

class PasskeyEntry(tk.Frame):
    """
    A password entry that shows a grey placeholder when empty,
    switches to masked (•) input when the user types.
    Exposes .get() which always returns the real value or "".
    """
    PLACEHOLDER_ENC = "Passkey for encryption"
    PLACEHOLDER_DEC = "Passkey for decryption"

    def __init__(self, parent, placeholder="Passkey", **kw):
        super().__init__(parent, bg=parent["bg"])
        self._placeholder = placeholder
        self._is_placeholder = True

        self._var = tk.StringVar()
        self._entry = tk.Entry(self, textvariable=self._var,
                               bg=WHITE, fg=SUBTEXT,
                               insertbackground=TEXT,
                               relief="solid", bd=1,
                               font=("Helvetica", 10), **kw)
        self._entry.pack(fill="x")
        self._entry.insert(0, placeholder)

        self._entry.bind("<FocusIn>",  self._on_focus_in)
        self._entry.bind("<FocusOut>", self._on_focus_out)

    def _on_focus_in(self, _):
        if self._is_placeholder:
            self._entry.delete(0, "end")
            self._entry.config(fg=TEXT, show="•")
            self._is_placeholder = False

    def _on_focus_out(self, _):
        if self._entry.get() == "":
            self._entry.config(show="", fg=SUBTEXT)
            self._entry.insert(0, self._placeholder)
            self._is_placeholder = True

    def get(self) -> str:
        """Return actual passkey, or '' if empty / placeholder."""
        if self._is_placeholder:
            return ""
        return self._entry.get()

    def set_state(self, state: str):
        self._entry.config(state=state)

    def clear(self):
        self._entry.config(state="normal")
        self._entry.delete(0, "end")
        self._entry.config(show="", fg=SUBTEXT)
        self._entry.insert(0, self._placeholder)
        self._is_placeholder = True


# ══════════════════════════════════════════════════════════
#  ENCRYPT PANEL
# ══════════════════════════════════════════════════════════

class EncryptPanel(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=BG)
        self._input_path = None
        self._enc_bytes  = None
        self._orig_name  = None
        self._build()

    def _build(self):
        _lbl(self, "🔒  Encrypt Image Online", size=15, bold=True,
             fg=HEADING).pack(anchor="center", pady=(0, 4))
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", pady=(0, 12))

        card  = _card(self)
        card.pack(fill="both", expand=True, padx=4, pady=4)
        inner = tk.Frame(card, bg=WHITE, padx=18, pady=16)
        inner.pack(fill="both", expand=True)

        # File chooser
        _lbl(inner, "Choose image (Max 10MB)").pack(anchor="w")
        frow = tk.Frame(inner, bg=WHITE,
                        highlightbackground="#5050ff", highlightthickness=2)
        frow.pack(fill="x", pady=(4, 12))
        _outline_btn(frow, "Browse...", self._browse, width=8).pack(side="left")
        self._file_lbl = _lbl(frow, "No file selected.", fg=SUBTEXT)
        self._file_lbl.pack(side="left", padx=8)

        # Preview (hidden until file chosen)
        self._preview_frame = tk.Frame(inner, bg=WHITE)
        _lbl(self._preview_frame, "Preview", fg=SUBTEXT).pack(anchor="w", pady=(0, 4))
        self._thumb = tk.Label(self._preview_frame, bg="#111111",
                               width=THUMB_W, height=THUMB_H,
                               highlightbackground=BORDER, highlightthickness=1)
        self._thumb.pack()

        # Passkey
        self._use_key = tk.BooleanVar(value=False)
        tk.Checkbutton(inner, text=" Encrypt with a secret key  ℹ",
                       variable=self._use_key, command=self._toggle_key,
                       bg=WHITE, fg=TEXT, font=("Helvetica", 10),
                       activebackground=WHITE, selectcolor=WHITE).pack(anchor="w", pady=(8, 2))

        self._passkey = PasskeyEntry(inner,
                                     placeholder=PasskeyEntry.PLACEHOLDER_ENC,
                                     width=42)
        self._passkey.pack(fill="x", pady=(2, 12))
        self._passkey.set_state("disabled")

        # Buttons
        brow = tk.Frame(inner, bg=WHITE)
        brow.pack(anchor="w", pady=(0, 10))
        _orange_btn(brow, "Encrypt", self._encrypt, width=10).pack(side="left")
        _outline_btn(brow, "Reset",   self._reset,   width=8).pack(side="left", padx=(8, 0))

        # Info
        self._info = _info_box(inner, "After encryption, download the .enc file or copy Base64.")
        self._info.pack(fill="x", pady=(4, 8))

        # Result row (hidden)
        self._result_frame = tk.Frame(inner, bg=WHITE)
        self._size_lbl = _lbl(self._result_frame, "", fg=SUBTEXT, size=9)
        self._size_lbl.pack(anchor="w", pady=(4, 4))
        drow = tk.Frame(self._result_frame, bg=WHITE)
        drow.pack(anchor="w")
        _orange_btn(drow, "Download .enc", self._download,  width=14).pack(side="left")
        _outline_btn(drow, "Copy Base64", self._copy_b64, width=12).pack(side="left", padx=(8, 0))

    # ──────────────────────────────────────────────────────
    def _toggle_key(self):
        self._passkey.set_state("normal" if self._use_key.get() else "disabled")

    def _browse(self):
        path = filedialog.askopenfilename(
            title="Choose image",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp *.tiff *.webp"),
                       ("All", "*.*")])
        if not path:
            return
        if os.path.getsize(path) > 10 * 1024 * 1024:
            messagebox.showerror("Error", "File exceeds 10MB limit.")
            return

        self._input_path = path
        self._orig_name  = os.path.basename(path)
        self._file_lbl.config(text=self._orig_name, fg=TEXT)

        try:
            img = Image.open(path).convert("RGB")
            img.thumbnail((THUMB_W, THUMB_H), Image.LANCZOS)
            photo = ImageTk.PhotoImage(img)
            self._thumb.config(image=photo, text="")
            self._thumb.image = photo
        except Exception:
            self._thumb.config(text="Preview unavailable", fg=SUBTEXT)

        self._preview_frame.pack(fill="x", pady=(0, 10), before=self._info)
        self._enc_bytes = None
        self._result_frame.pack_forget()

    def _encrypt(self):
        if not self._input_path:
            messagebox.showerror("Error", "Please choose an image first.")
            return

        passkey = ""
        if self._use_key.get():
            passkey = self._passkey.get()
            if not passkey:
                messagebox.showerror("Error", "Please enter a passkey.")
                return

        def run():
            try:
                enc = encrypt_image(Image.open(self._input_path), passkey)
                self.after(0, lambda: self._on_encrypted(enc))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Error", str(e)))

        threading.Thread(target=run, daemon=True).start()

    def _on_encrypted(self, enc_bytes: bytes):
        self._enc_bytes = enc_bytes
        self._size_lbl.config(text=f"Encrypted image ready — {len(enc_bytes)/1024:.2f} KB")
        self._result_frame.pack(fill="x", pady=(4, 0))

    def _download(self):
        if not self._enc_bytes:
            return
        base = os.path.splitext(self._orig_name)[0] if self._orig_name else "encrypted"
        path = filedialog.asksaveasfilename(
            defaultextension=".enc", initialfile=f"{base}.enc",
            filetypes=[("Encrypted", "*.enc"), ("All", "*.*")])
        if path:
            with open(path, "wb") as f:
                f.write(self._enc_bytes)
            messagebox.showinfo("Saved", f"Saved to:\n{path}")

    def _copy_b64(self):
        if not self._enc_bytes:
            return
        self.clipboard_clear()
        self.clipboard_append(base64.b64encode(self._enc_bytes).decode())
        messagebox.showinfo("Copied", "Base64 copied to clipboard.")

    def _reset(self):
        self._input_path = None
        self._enc_bytes  = None
        self._orig_name  = None
        self._file_lbl.config(text="No file selected.", fg=SUBTEXT)
        self._preview_frame.pack_forget()
        self._result_frame.pack_forget()
        self._passkey.clear()
        self._passkey.set_state("disabled")
        self._use_key.set(False)


# ══════════════════════════════════════════════════════════
#  DECRYPT PANEL
# ══════════════════════════════════════════════════════════

class DecryptPanel(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=BG)
        self._enc_path   = None
        self._result_img = None
        self._orig_name  = None
        self._build()

    def _build(self):
        _lbl(self, "🔒  Decrypt Image Online", size=15, bold=True,
             fg=HEADING).pack(anchor="center", pady=(0, 4))
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", pady=(0, 12))

        card  = _card(self)
        card.pack(fill="both", expand=True, padx=4, pady=4)
        inner = tk.Frame(card, bg=WHITE, padx=18, pady=16)
        inner.pack(fill="both", expand=True)

        # File chooser
        _lbl(inner, "Encrypted file (.enc / .txt)").pack(anchor="w")
        frow = tk.Frame(inner, bg=WHITE,
                        highlightbackground=BORDER, highlightthickness=1)
        frow.pack(fill="x", pady=(4, 12))
        _outline_btn(frow, "Browse...", self._browse, width=8).pack(side="left")
        self._file_lbl = _lbl(frow, "No file selected.", fg=SUBTEXT)
        self._file_lbl.pack(side="left", padx=8)

        # Passkey
        self._use_key = tk.BooleanVar(value=False)
        tk.Checkbutton(inner, text=" Secret key required  ℹ",
                       variable=self._use_key, command=self._toggle_key,
                       bg=WHITE, fg=TEXT, font=("Helvetica", 10),
                       activebackground=WHITE, selectcolor=WHITE).pack(anchor="w", pady=(4, 2))

        self._passkey = PasskeyEntry(inner,
                                     placeholder=PasskeyEntry.PLACEHOLDER_DEC,
                                     width=42)
        self._passkey.pack(fill="x", pady=(2, 12))
        self._passkey.set_state("disabled")

        # Buttons
        brow = tk.Frame(inner, bg=WHITE)
        brow.pack(anchor="w", pady=(0, 10))
        _orange_btn(brow, "Decrypt", self._decrypt, width=10).pack(side="left")
        _outline_btn(brow, "Reset",   self._reset,   width=8).pack(side="left", padx=(8, 0))

        # Warning
        _warn_box(inner,
            "If decryption fails, the passkey may be incorrect or file corrupted."
        ).pack(fill="x", pady=(4, 8))

        # Result (hidden)
        self._result_frame = tk.Frame(inner, bg=WHITE)
        self._name_lbl = _lbl(self._result_frame, "", fg=SUBTEXT, size=9)
        self._name_lbl.pack(anchor="center", pady=(4, 4))
        self._thumb = tk.Label(self._result_frame, bg="#111111",
                               width=THUMB_W, height=THUMB_H,
                               highlightbackground=BORDER, highlightthickness=1)
        self._thumb.pack()
        _orange_btn(self._result_frame, "Download Image",
                    self._download, width=16).pack(pady=(10, 4))

    # ──────────────────────────────────────────────────────
    def _toggle_key(self):
        self._passkey.set_state("normal" if self._use_key.get() else "disabled")

    def _browse(self):
        path = filedialog.askopenfilename(
            title="Choose encrypted file",
            filetypes=[("Encrypted", "*.enc *.txt"), ("All", "*.*")])
        if path:
            self._enc_path  = path
            self._orig_name = os.path.basename(path)
            self._file_lbl.config(text=self._orig_name, fg=TEXT)
            self._result_frame.pack_forget()

    def _decrypt(self):
        if not self._enc_path:
            messagebox.showerror("Error", "Please choose an encrypted file first.")
            return

        passkey = ""
        if self._use_key.get():
            passkey = self._passkey.get()
            if not passkey:
                messagebox.showerror("Error", "Please enter the passkey.")
                return

        def run():
            try:
                with open(self._enc_path, "rb") as f:
                    data = f.read()
                img = decrypt_bytes(data, passkey)
                self.after(0, lambda: self._on_decrypted(img))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror(
                    "Decryption Failed",
                    f"Passkey may be incorrect or file corrupted.\n\n{e}"))

        threading.Thread(target=run, daemon=True).start()

    def _on_decrypted(self, img: Image.Image):
        self._result_img = img
        preview = img.copy()
        preview.thumbnail((THUMB_W, THUMB_H), Image.LANCZOS)
        photo = ImageTk.PhotoImage(preview)
        self._thumb.config(image=photo, text="")
        self._thumb.image = photo
        base = os.path.splitext(self._orig_name)[0] if self._orig_name else "decrypted"
        self._name_lbl.config(text=f"{base}.png")
        self._result_frame.pack(fill="x", pady=(8, 0))

    def _download(self):
        if not self._result_img:
            return
        base = os.path.splitext(self._orig_name)[0] if self._orig_name else "decrypted"
        path = filedialog.asksaveasfilename(
            defaultextension=".png", initialfile=f"{base}.png",
            filetypes=[("PNG", "*.png"), ("All", "*.*")])
        if path:
            self._result_img.save(path)
            messagebox.showinfo("Saved", f"Saved to:\n{path}")

    def _reset(self):
        self._enc_path   = None
        self._result_img = None
        self._orig_name  = None
        self._file_lbl.config(text="No file selected.", fg=SUBTEXT)
        self._result_frame.pack_forget()
        self._passkey.clear()
        self._passkey.set_state("disabled")
        self._use_key.set(False)


# ══════════════════════════════════════════════════════════
#  MAIN WINDOW
# ══════════════════════════════════════════════════════════

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Image Encryption Tool")
        self.configure(bg=BG)
        self.resizable(True, True)

        wrapper = tk.Frame(self, bg=BG, padx=24, pady=20)
        wrapper.pack(fill="both", expand=True)

        EncryptPanel(wrapper).grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        tk.Frame(wrapper, bg=BORDER, width=1).grid(row=0, column=1, sticky="ns", padx=4)
        DecryptPanel(wrapper).grid(row=0, column=2, sticky="nsew", padx=(12, 0))

        wrapper.columnconfigure(0, weight=1)
        wrapper.columnconfigure(2, weight=1)

        self.update_idletasks()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        w, h   = 1060, 680
        self.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")


if __name__ == "__main__":
    App().mainloop()
