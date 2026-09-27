"""
Image Encryption Tool
=====================
Two-panel GUI — Encrypt (left) | Decrypt (right)

Encryption: XOR pixel values with a key derived from a passkey string,
            then shuffle pixel positions. Output saved as .enc file.
Decryption: Load .enc file, reverse the process, save as original image.

Run with:
  python main.py
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
    """Derive a stable integer seed from a passkey string."""
    return int(hashlib.sha256(passkey.encode()).hexdigest(), 16) % (2**32)


def _shuffle_indices(total: int, seed: int) -> list:
    indices = list(range(total))
    random.seed(seed)
    random.shuffle(indices)
    return indices


def encrypt_image(img: Image.Image, passkey: str) -> bytes:
    """
    Encrypt a PIL image and return raw encrypted bytes.
    Format: [4B width][4B height][4B mode_len][mode bytes][pixel bytes]
    """
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGB")

    w, h   = img.size
    mode   = img.mode.encode()
    pixels = np.array(img, dtype=np.uint8)

    seed    = _derive_key(passkey)
    key_xor = seed % 256

    # XOR
    xored = (pixels ^ key_xor).astype(np.uint8)

    # Shuffle
    flat      = xored.reshape(-1, pixels.shape[2])
    indices   = _shuffle_indices(len(flat), seed)
    shuffled  = flat[indices].flatten()

    header = struct.pack(">III", w, h, len(mode)) + mode
    return header + shuffled.tobytes()


def decrypt_bytes(enc_bytes: bytes, passkey: str) -> Image.Image:
    """Decrypt raw encrypted bytes back into a PIL image."""
    offset = 0
    w, h, mode_len = struct.unpack(">III", enc_bytes[offset:offset + 12])
    offset += 12
    mode   = enc_bytes[offset:offset + mode_len].decode()
    offset += mode_len

    channels = len(mode)           # RGB=3, RGBA=4
    total_px = w * h

    seed    = _derive_key(passkey)
    key_xor = seed % 256

    flat_enc = np.frombuffer(enc_bytes[offset:], dtype=np.uint8).reshape(total_px, channels)

    # Unshuffle
    indices  = _shuffle_indices(total_px, seed)
    restored = np.empty_like(flat_enc)
    for orig, shuf in enumerate(indices):
        restored[orig] = flat_enc[shuf]

    # XOR back
    pixels = (restored ^ key_xor).astype(np.uint8).reshape(h, w, channels)
    return Image.fromarray(pixels, mode)


# ══════════════════════════════════════════════════════════
#  THEME
# ══════════════════════════════════════════════════════════

BG       = "#f5f5f5"
WHITE    = "#ffffff"
BORDER   = "#dddddd"
TEXT     = "#222222"
SUBTEXT  = "#666666"
ORANGE   = "#e8620a"
ORANGE_H = "#ff7a1f"
BTN_OUT  = "#ffffff"
INFO_BG  = "#e8f4fd"
INFO_FG  = "#1a6ea8"
WARN_BG  = "#fff9e6"
WARN_FG  = "#7a6000"
HEADING  = "#111111"
THUMB_W  = 340
THUMB_H  = 200


def _card(parent, **kw):
    return tk.Frame(parent, bg=WHITE, bd=0,
                    highlightbackground=BORDER, highlightthickness=1, **kw)


def _label(parent, text, size=10, bold=False, color=TEXT, **kw):
    font = ("Helvetica", size, "bold" if bold else "normal")
    return tk.Label(parent, text=text, bg=parent["bg"],
                    fg=color, font=font, **kw)


def _entry(parent, textvariable, show=None, width=38):
    e = tk.Entry(parent, textvariable=textvariable,
                 bg=WHITE, fg=TEXT, insertbackground=TEXT,
                 relief="solid", bd=1, font=("Helvetica", 10),
                 width=width, show=show or "")
    e.config(highlightthickness=0)
    return e


def _orange_btn(parent, text, command, width=12):
    b = tk.Button(parent, text=text, command=command,
                  bg=ORANGE, fg="white", activebackground=ORANGE_H,
                  activeforeground="white", relief="flat", bd=0,
                  font=("Helvetica", 10, "bold"), cursor="hand2",
                  padx=14, pady=7, width=width)
    b.bind("<Enter>", lambda e: b.config(bg=ORANGE_H))
    b.bind("<Leave>", lambda e: b.config(bg=ORANGE))
    return b


def _outline_btn(parent, text, command, width=12):
    b = tk.Button(parent, text=text, command=command,
                  bg=BTN_OUT, fg=TEXT, activebackground="#eeeeee",
                  activeforeground=TEXT, relief="solid", bd=1,
                  font=("Helvetica", 10), cursor="hand2",
                  padx=14, pady=7, width=width)
    return b


def _info_box(parent, text):
    f = tk.Frame(parent, bg=INFO_BG,
                 highlightbackground="#a8d4f0", highlightthickness=1)
    tk.Label(f, text=text, bg=INFO_BG, fg=INFO_FG,
             font=("Helvetica", 9), wraplength=320, justify="left",
             padx=10, pady=8).pack()
    return f


def _warn_box(parent, text):
    f = tk.Frame(parent, bg=WARN_BG,
                 highlightbackground="#e0c96e", highlightthickness=1)
    tk.Label(f, text=text, bg=WARN_BG, fg=WARN_FG,
             font=("Helvetica", 9), wraplength=320, justify="left",
             padx=10, pady=8).pack()
    return f


def _divider(parent):
    tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", pady=8)


def _thumb_label(parent):
    lbl = tk.Label(parent, bg="#111111", width=THUMB_W, height=THUMB_H,
                   text="", cursor="arrow",
                   highlightbackground=BORDER, highlightthickness=1)
    return lbl


# ══════════════════════════════════════════════════════════
#  ENCRYPT PANEL
# ══════════════════════════════════════════════════════════

class EncryptPanel(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=BG)
        self._input_path  = None
        self._enc_bytes   = None
        self._orig_name   = None

        self._build()

    def _build(self):
        # Heading
        _label(self, "🔒  Encrypt Image Online", size=15, bold=True,
               color=HEADING).pack(anchor="center", pady=(0, 4))
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", pady=(0, 12))

        card = _card(self)
        card.pack(fill="both", expand=True, padx=4, pady=4)
        inner = tk.Frame(card, bg=WHITE, padx=18, pady=16)
        inner.pack(fill="both", expand=True)

        # File row
        _label(inner, "Choose image (Max 10MB)", size=10).pack(anchor="w")
        file_row = tk.Frame(inner, bg=WHITE,
                            highlightbackground="#5050ff",
                            highlightthickness=2)
        file_row.pack(fill="x", pady=(4, 12))
        _outline_btn(file_row, "Browse...", self._browse, width=8).pack(side="left")
        self._file_lbl = _label(file_row, "No file selected.", color=SUBTEXT)
        self._file_lbl.pack(side="left", padx=8)

        # Preview
        self._preview_frame = tk.Frame(inner, bg=WHITE)
        self._preview_lbl   = _label(self._preview_frame, "Preview", size=10, bold=False, color=SUBTEXT)
        self._thumb         = _thumb_label(self._preview_frame)

        # Secret key checkbox
        self._use_key = tk.BooleanVar(value=False)
        cb = tk.Checkbutton(inner, text=" Encrypt with a secret key  ℹ",
                            variable=self._use_key, command=self._toggle_key,
                            bg=WHITE, fg=TEXT, font=("Helvetica", 10),
                            activebackground=WHITE, selectcolor=WHITE,
                            cursor="hand2")
        cb.pack(anchor="w", pady=(4, 2))

        self._key_var   = tk.StringVar()
        self._key_entry = _entry(inner, self._key_var, show="•")
        self._key_entry.insert(0, "Passkey for encryption")
        self._key_entry.config(fg=SUBTEXT)
        self._key_entry.bind("<FocusIn>",  self._key_focus_in)
        self._key_entry.bind("<FocusOut>", self._key_focus_out)
        self._key_entry.pack(fill="x", pady=(2, 12))
        self._key_entry.config(state="disabled")

        # Buttons
        btn_row = tk.Frame(inner, bg=WHITE)
        btn_row.pack(anchor="w", pady=(0, 10))
        _orange_btn(btn_row, "Encrypt", self._encrypt, width=10).pack(side="left")
        _outline_btn(btn_row, "Reset", self._reset, width=8).pack(side="left", padx=(8, 0))

        # Info box
        self._info = _info_box(inner, "After encryption, download the .enc file or copy Base64.")
        self._info.pack(fill="x", pady=(4, 8))

        # Result row (hidden until encrypted)
        self._result_frame = tk.Frame(inner, bg=WHITE)
        self._size_lbl     = _label(self._result_frame, "", color=SUBTEXT, size=9)
        self._size_lbl.pack(anchor="w", pady=(4, 4))
        dl_row = tk.Frame(self._result_frame, bg=WHITE)
        dl_row.pack(anchor="w")
        self._dl_btn  = _orange_btn(dl_row, "Download .enc", self._download, width=14)
        self._dl_btn.pack(side="left")
        self._b64_btn = _outline_btn(dl_row, "Copy Base64", self._copy_b64, width=12)
        self._b64_btn.pack(side="left", padx=(8, 0))

    # ── helpers ──────────────────────────────────────────

    def _toggle_key(self):
        if self._use_key.get():
            self._key_entry.config(state="normal")
            if self._key_var.get() == "":
                self._key_entry.config(fg=SUBTEXT)
        else:
            self._key_entry.config(state="disabled")

    def _key_focus_in(self, _):
        if self._key_entry.get() == "Passkey for encryption":
            self._key_entry.delete(0, "end")
            self._key_entry.config(fg=TEXT, show="•")

    def _key_focus_out(self, _):
        if self._key_entry.get() == "":
            self._key_entry.config(show="", fg=SUBTEXT)
            self._key_entry.insert(0, "Passkey for encryption")

    def _browse(self):
        path = filedialog.askopenfilename(
            title="Choose image",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp *.tiff *.webp"),
                       ("All", "*.*")]
        )
        if not path:
            return
        if os.path.getsize(path) > 10 * 1024 * 1024:
            messagebox.showerror("Error", "File exceeds 10MB limit.")
            return
        self._input_path = path
        self._orig_name  = os.path.basename(path)
        self._file_lbl.config(text=self._orig_name, fg=TEXT)

        # Show preview
        try:
            img = Image.open(path).convert("RGB")
            img.thumbnail((THUMB_W, THUMB_H), Image.LANCZOS)
            photo = ImageTk.PhotoImage(img)
            self._thumb.config(image=photo, text="")
            self._thumb.image = photo
        except Exception:
            self._thumb.config(text="Preview unavailable", fg=SUBTEXT)

        self._preview_lbl.pack(anchor="w", pady=(8, 4))
        self._thumb.pack()
        self._preview_frame.pack(fill="x", pady=(0, 10),
                                 before=self._info)

        # Reset result
        self._enc_bytes = None
        self._result_frame.pack_forget()

    def _encrypt(self):
        if not self._input_path:
            messagebox.showerror("Error", "Please choose an image first.")
            return

        passkey = ""
        if self._use_key.get():
            raw = self._key_entry.get()
            if raw in ("", "Passkey for encryption"):
                messagebox.showerror("Error", "Please enter a passkey.")
                return
            passkey = raw

        def run():
            try:
                img = Image.open(self._input_path)
                enc = encrypt_image(img, passkey)
                self.after(0, lambda: self._on_encrypted(enc))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Error", str(e)))

        threading.Thread(target=run, daemon=True).start()

    def _on_encrypted(self, enc_bytes: bytes):
        self._enc_bytes = enc_bytes
        kb = len(enc_bytes) / 1024
        self._size_lbl.config(
            text=f"Encrypted image ready — {kb:.2f} KB")
        self._result_frame.pack(fill="x", pady=(4, 0))

    def _download(self):
        if not self._enc_bytes:
            return
        base = os.path.splitext(self._orig_name)[0] if self._orig_name else "encrypted"
        path = filedialog.asksaveasfilename(
            defaultextension=".enc",
            initialfile=f"{base}.enc",
            filetypes=[("Encrypted file", "*.enc"), ("All", "*.*")]
        )
        if path:
            with open(path, "wb") as f:
                f.write(self._enc_bytes)
            messagebox.showinfo("Saved", f"Saved to:\n{path}")

    def _copy_b64(self):
        if not self._enc_bytes:
            return
        b64 = base64.b64encode(self._enc_bytes).decode()
        self.clipboard_clear()
        self.clipboard_append(b64)
        messagebox.showinfo("Copied", "Base64 string copied to clipboard.")

    def _reset(self):
        self._input_path = None
        self._enc_bytes  = None
        self._orig_name  = None
        self._file_lbl.config(text="No file selected.", fg=SUBTEXT)
        self._preview_frame.pack_forget()
        self._result_frame.pack_forget()
        self._key_var.set("")
        self._key_entry.config(show="", fg=SUBTEXT)
        self._key_entry.delete(0, "end")
        self._key_entry.insert(0, "Passkey for encryption")
        self._use_key.set(False)
        self._key_entry.config(state="disabled")


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
        # Heading
        _label(self, "🔒  Decrypt Image Online", size=15, bold=True,
               color=HEADING).pack(anchor="center", pady=(0, 4))
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", pady=(0, 12))

        card = _card(self)
        card.pack(fill="both", expand=True, padx=4, pady=4)
        inner = tk.Frame(card, bg=WHITE, padx=18, pady=16)
        inner.pack(fill="both", expand=True)

        # File row
        _label(inner, "Encrypted file (.enc / .txt)", size=10).pack(anchor="w")
        file_row = tk.Frame(inner, bg=WHITE,
                            highlightbackground=BORDER,
                            highlightthickness=1)
        file_row.pack(fill="x", pady=(4, 12))
        _outline_btn(file_row, "Browse...", self._browse, width=8).pack(side="left")
        self._file_lbl = _label(file_row, "No file selected.", color=SUBTEXT)
        self._file_lbl.pack(side="left", padx=8)

        # Secret key checkbox
        self._use_key = tk.BooleanVar(value=False)
        cb = tk.Checkbutton(inner, text=" Secret key required  ℹ",
                            variable=self._use_key, command=self._toggle_key,
                            bg=WHITE, fg=TEXT, font=("Helvetica", 10),
                            activebackground=WHITE, selectcolor=WHITE,
                            cursor="hand2")
        cb.pack(anchor="w", pady=(4, 2))

        self._key_var   = tk.StringVar()
        self._key_entry = _entry(inner, self._key_var, show="•")
        self._key_entry.insert(0, "Passkey for decryption")
        self._key_entry.config(fg=SUBTEXT)
        self._key_entry.bind("<FocusIn>",  self._key_focus_in)
        self._key_entry.bind("<FocusOut>", self._key_focus_out)
        self._key_entry.pack(fill="x", pady=(2, 12))
        self._key_entry.config(state="disabled")

        # Buttons
        btn_row = tk.Frame(inner, bg=WHITE)
        btn_row.pack(anchor="w", pady=(0, 10))
        _orange_btn(btn_row, "Decrypt", self._decrypt, width=10).pack(side="left")
        _outline_btn(btn_row, "Reset", self._reset, width=8).pack(side="left", padx=(8, 0))

        # Warning box
        self._warn = _warn_box(inner,
            "If decryption fails, the passkey may be incorrect or file corrupted.")
        self._warn.pack(fill="x", pady=(4, 8))

        # Result (hidden)
        self._result_frame = tk.Frame(inner, bg=WHITE)
        self._name_lbl     = _label(self._result_frame, "", color=SUBTEXT, size=9)
        self._name_lbl.pack(anchor="center", pady=(4, 4))
        self._thumb        = _thumb_label(self._result_frame)
        self._thumb.pack()
        _orange_btn(self._result_frame, "Download Image",
                    self._download, width=16).pack(pady=(10, 4))

    # ── helpers ──────────────────────────────────────────

    def _toggle_key(self):
        if self._use_key.get():
            self._key_entry.config(state="normal")
        else:
            self._key_entry.config(state="disabled")

    def _key_focus_in(self, _):
        if self._key_entry.get() == "Passkey for decryption":
            self._key_entry.delete(0, "end")
            self._key_entry.config(fg=TEXT, show="•")

    def _key_focus_out(self, _):
        if self._key_entry.get() == "":
            self._key_entry.config(show="", fg=SUBTEXT)
            self._key_entry.insert(0, "Passkey for decryption")

    def _browse(self):
        path = filedialog.askopenfilename(
            title="Choose encrypted file",
            filetypes=[("Encrypted", "*.enc *.txt"), ("All", "*.*")]
        )
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
            raw = self._key_entry.get()
            if raw in ("", "Passkey for decryption"):
                messagebox.showerror("Error", "Please enter the passkey.")
                return
            passkey = raw

        def run():
            try:
                with open(self._enc_path, "rb") as f:
                    data = f.read()
                img = decrypt_bytes(data, passkey)
                self.after(0, lambda: self._on_decrypted(img))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror(
                    "Decryption Failed",
                    f"Could not decrypt the file.\nPasskey may be wrong or file corrupted.\n\n{e}"
                ))

        threading.Thread(target=run, daemon=True).start()

    def _on_decrypted(self, img: Image.Image):
        self._result_img = img

        # Show thumbnail
        preview = img.copy()
        preview.thumbnail((THUMB_W, THUMB_H), Image.LANCZOS)
        photo = ImageTk.PhotoImage(preview)
        self._thumb.config(image=photo, text="")
        self._thumb.image = photo

        # Derive original filename
        base = os.path.splitext(self._orig_name)[0] if self._orig_name else "decrypted"
        self._name_lbl.config(text=f"{base}.png")

        self._result_frame.pack(fill="x", pady=(8, 0))

    def _download(self):
        if not self._result_img:
            return
        base = os.path.splitext(self._orig_name)[0] if self._orig_name else "decrypted"
        path = filedialog.asksaveasfilename(
            defaultextension=".png",
            initialfile=f"{base}.png",
            filetypes=[("PNG", "*.png"), ("All", "*.*")]
        )
        if path:
            self._result_img.save(path)
            messagebox.showinfo("Saved", f"Saved to:\n{path}")

    def _reset(self):
        self._enc_path   = None
        self._result_img = None
        self._orig_name  = None
        self._file_lbl.config(text="No file selected.", fg=SUBTEXT)
        self._result_frame.pack_forget()
        self._key_var.set("")
        self._key_entry.config(show="", fg=SUBTEXT)
        self._key_entry.delete(0, "end")
        self._key_entry.insert(0, "Passkey for decryption")
        self._use_key.set(False)
        self._key_entry.config(state="disabled")


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

        enc = EncryptPanel(wrapper)
        enc.grid(row=0, column=0, sticky="nsew", padx=(0, 12))

        # Vertical divider
        tk.Frame(wrapper, bg=BORDER, width=1).grid(row=0, column=1, sticky="ns", padx=4)

        dec = DecryptPanel(wrapper)
        dec.grid(row=0, column=2, sticky="nsew", padx=(12, 0))

        wrapper.columnconfigure(0, weight=1)
        wrapper.columnconfigure(2, weight=1)

        self._center(1060, 680)

    def _center(self, w, h):
        self.update_idletasks()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")


if __name__ == "__main__":
    App().mainloop()
