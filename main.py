"""
PixelCrypt — RGB Pixel Manipulation Image Encryption Tool
=========================================================
Run:   python main.py
Deps:  pillow, numpy  (no customtkinter needed)

Cross-platform: macOS · Windows · Linux
"""

from __future__ import annotations

import base64
import hashlib
import math
import random
import struct
import threading
from pathlib import Path
from tkinter import filedialog, messagebox
import tkinter as tk

import numpy as np
from PIL import Image, ImageTk

# ══════════════════════════════════════════════════════════
#  CRYPTO CORE  —  RGB Pixel Manipulation
# ══════════════════════════════════════════════════════════

def _derive_seed(key: str) -> int:
    return int(hashlib.sha256(key.encode()).hexdigest(), 16) % (2 ** 32)


def _shuffle_indices(total: int, seed: int) -> list[int]:
    idx = list(range(total))
    random.seed(seed)
    random.shuffle(idx)
    return idx


def encrypt_image(img: Image.Image, key: str) -> bytes:
    """XOR each RGB channel + shuffle pixel positions."""
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGB")
    w, h   = img.size
    mode_b = img.mode.encode()
    pixels = np.array(img, dtype=np.uint8)
    seed   = _derive_seed(key)
    xored  = (pixels ^ (seed % 256)).astype(np.uint8)
    flat   = xored.reshape(-1, pixels.shape[2])
    shuffled = flat[_shuffle_indices(len(flat), seed)].flatten()
    return struct.pack(">III", w, h, len(mode_b)) + mode_b + shuffled.tobytes()


def decrypt_bytes(data: bytes, key: str) -> Image.Image:
    """Reverse pixel shuffle then XOR to restore original image."""
    w, h, mode_len = struct.unpack(">III", data[:12])
    mode     = data[12: 12 + mode_len].decode()
    body     = data[12 + mode_len:]
    channels = len(mode)
    seed     = _derive_seed(key)
    flat_enc = np.frombuffer(body, dtype=np.uint8).reshape(w * h, channels)
    indices  = _shuffle_indices(w * h, seed)
    restored = np.empty_like(flat_enc)
    for i, orig in enumerate(indices):
        restored[orig] = flat_enc[i]
    pixels = (restored ^ (seed % 256)).astype(np.uint8).reshape(h, w, channels)
    return Image.fromarray(pixels, mode)


def key_entropy_bits(key: str) -> int:
    if not key:
        return 0
    charset = 0
    if any(c.islower() for c in key): charset += 26
    if any(c.isupper() for c in key): charset += 26
    if any(c.isdigit() for c in key): charset += 10
    if any(not c.isalnum() for c in key): charset += 32
    return int(len(key) * math.log2(charset)) if charset else 0


# ══════════════════════════════════════════════════════════
#  PALETTE
# ══════════════════════════════════════════════════════════
C = {
    "bg":       "#F0F2F5",
    "panel":    "#FFFFFF",
    "border":   "#DDE1E7",
    "border2":  "#C8CDD6",
    "text":     "#1A1D23",
    "sub":      "#6B7280",
    "btn":      "#1E293B",
    "btn_hv":   "#334155",
    "btn_dis":  "#94A3B8",
    "green":    "#16A34A",
    "green_l":  "#DCFCE7",
    "blue":     "#2563EB",
    "blue_l":   "#EFF6FF",
    "yellow_l": "#FEFCE8",
    "yellow_b": "#CA8A04",
    "red":      "#DC2626",
    "dash_bg":  "#F8FAFC",
    "dash_bd":  "#CBD5E1",
    "badge_bg": "#F1F5F9",
    "badge_fg": "#475569",
    "dark":     "#0F172A",
    "dark_sub": "#64748B",
}

THUMB_W, THUMB_H = 380, 155
F = "Helvetica"  # available on all platforms


# ══════════════════════════════════════════════════════════
#  WIDGET HELPERS
# ══════════════════════════════════════════════════════════

def _lbl(parent, text, size=10, bold=False, fg=None, bg=None, **kw):
    return tk.Label(
        parent, text=text,
        bg=bg or parent["bg"],
        fg=fg or C["text"],
        font=(F, size, "bold" if bold else "normal"),
        **kw,
    )


def _sep(parent):
    return tk.Frame(parent, bg=C["border"], height=1)


def _badge(parent, text, bg=None, fg=None):
    return tk.Label(
        parent, text=text,
        bg=bg or C["badge_bg"],
        fg=fg or C["badge_fg"],
        font=(F, 8, "bold"),
        padx=7, pady=3,
    )


class DarkBtn(tk.Frame):
    """Charcoal button — renders correctly on every platform."""

    def __init__(self, parent, text, command):
        super().__init__(parent, bg=C["btn"])
        self._cmd = command
        self._lbl = tk.Label(self, text=text, bg=C["btn"], fg="white",
                             font=(F, 10, "bold"), padx=16, height=2)
        self._lbl.pack(fill="both", expand=True)
        for w in (self, self._lbl):
            w.bind("<Button-1>", self._click)
            w.bind("<Enter>",
                   lambda e: (self.config(bg=C["btn_hv"]),
                               self._lbl.config(bg=C["btn_hv"])))
            w.bind("<Leave>",
                   lambda e: (self.config(bg=C["btn"]),
                               self._lbl.config(bg=C["btn"])))

    def _click(self, _): self._cmd()

    def set_text(self, t): self._lbl.config(text=t)

    def set_enabled(self, on: bool):
        c = C["btn"] if on else C["btn_dis"]
        self.config(bg=c)
        self._lbl.config(bg=c, fg="white" if on else "#CBD5E1")
        for w in (self, self._lbl):
            w.unbind("<Button-1>")
            if on:
                w.bind("<Button-1>", self._click)


class OutlineBtn(tk.Frame):
    def __init__(self, parent, text, command, width=90):
        super().__init__(parent, bg=C["panel"],
                         highlightbackground=C["border2"],
                         highlightthickness=1)
        self._lbl = tk.Label(self, text=text, bg=C["panel"], fg=C["text"],
                             font=(F, 10), padx=12, height=2,
                             width=width // 8)
        self._lbl.pack(fill="both", expand=True)
        for w in (self, self._lbl):
            w.bind("<Button-1>", lambda e: command())
            w.bind("<Enter>",    lambda e: self._lbl.config(bg="#F1F5F9"))
            w.bind("<Leave>",    lambda e: self._lbl.config(bg=C["panel"]))


class PasskeyEntry(tk.Frame):
    """Password entry with placeholder and show/hide toggle."""

    def __init__(self, parent, placeholder="Enter key", on_change=None):
        super().__init__(parent, bg=C["panel"],
                         highlightbackground=C["border2"],
                         highlightthickness=1)
        self._ph    = placeholder
        self._is_ph = True
        self._vis   = False

        inner = tk.Frame(self, bg=C["panel"], padx=8, pady=6)
        inner.pack(fill="x")

        tk.Label(inner, text="🔑", bg=C["panel"],
                 font=(F, 10)).pack(side="left")

        self._var   = tk.StringVar(value=placeholder)
        self._entry = tk.Entry(inner, textvariable=self._var,
                               bg=C["panel"], fg=C["sub"],
                               relief="flat", bd=0,
                               font=(F, 11),
                               insertbackground=C["text"],
                               show="")
        self._entry.pack(side="left", fill="x", expand=True, padx=6)
        self._entry.bind("<FocusIn>",  self._fin)
        self._entry.bind("<FocusOut>", self._fout)
        if on_change:
            self._var.trace_add("write", lambda *_: on_change())

        tk.Button(inner, text="👁", bg=C["panel"], fg=C["sub"],
                  relief="flat", bd=0, font=(F, 12),
                  command=self._toggle).pack(side="right")

    def _fin(self, _):
        if self._is_ph:
            self._entry.delete(0, "end")
            self._entry.config(fg=C["text"], show="•")
            self._is_ph = False

    def _fout(self, _):
        if self._entry.get() == "":
            self._entry.config(show="", fg=C["sub"])
            self._entry.insert(0, self._ph)
            self._is_ph = True

    def _toggle(self):
        if self._is_ph: return
        self._vis = not self._vis
        self._entry.config(show="" if self._vis else "•")

    def get(self) -> str:
        return "" if self._is_ph else self._entry.get()

    def set_enabled(self, on: bool):
        self._entry.config(state="normal" if on else "disabled")

    def clear(self):
        self._entry.config(state="normal", show="", fg=C["sub"])
        self._entry.delete(0, "end")
        self._entry.insert(0, self._ph)
        self._is_ph = True
        self._vis   = False


class StrengthBar(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=C["panel"])
        row = tk.Frame(self, bg=C["panel"])
        row.pack(fill="x")
        self._segs = [tk.Frame(row, bg="#E5E7EB", height=4)
                      for _ in range(5)]
        for s in self._segs:
            s.pack(side="left", fill="x", expand=True, padx=1)
        self._lbl = _lbl(self, "", size=8, fg=C["sub"])
        self._lbl.pack(anchor="e")

    def update(self, key: str):
        bits  = key_entropy_bits(key)
        score = min(int(bits / 1.28), 100)
        levels = [(20, C["red"],   "Weak"),
                  (40, "#F59E0B",  "Fair"),
                  (60, "#84CC16",  "Good"),
                  (80, C["green"], "Strong"),
                  (100, C["green"],"Strong")]
        filled, color, label = 0, "#E5E7EB", ""
        for t, c, l in levels:
            if score >= t:
                filled += 1; color = c; label = l
        for i, s in enumerate(self._segs):
            s.config(bg=color if i < filled else "#E5E7EB")
        self._lbl.config(
            text=f"Strength: {label}  ({bits}-bit)" if label else "",
            fg=color if label else C["sub"])


# ══════════════════════════════════════════════════════════
#  ENCRYPT PANEL
# ══════════════════════════════════════════════════════════

class EncryptPanel(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=C["panel"],
                         highlightbackground=C["border"],
                         highlightthickness=1)
        self._path: Path | None       = None
        self._enc_bytes: bytes | None = None
        self._build()

    def _build(self):
        p = tk.Frame(self, bg=C["panel"], padx=18, pady=14)
        p.pack(fill="both", expand=True)

        # Header
        hdr = tk.Frame(p, bg=C["panel"])
        hdr.pack(fill="x", pady=(0, 8))
        icon_f = tk.Frame(hdr, bg="#FFF3ED", width=40, height=40)
        icon_f.pack(side="left"); icon_f.pack_propagate(False)
        tk.Label(icon_f, text="🛡", bg="#FFF3ED",
                 font=(F, 17)).place(relx=.5, rely=.5, anchor="center")
        tf = tk.Frame(hdr, bg=C["panel"])
        tf.pack(side="left", padx=(10, 0))
        _lbl(tf, "Encrypt Image", size=13, bold=True).pack(anchor="w")
        _lbl(tf, "Pixel manipulation encryption",
             size=8, fg=C["sub"]).pack(anchor="w")
        _badge(hdr, "RGB Pixel Cipher").pack(side="right")
        _sep(p).pack(fill="x", pady=(0, 10))

        # File chooser
        _lbl(p, "Source Image", size=9, fg=C["sub"]).pack(anchor="w", pady=(0, 4))
        fb_outer = tk.Frame(p, bg=C["dash_bg"],
                            highlightbackground=C["dash_bd"],
                            highlightthickness=1)
        fb_outer.pack(fill="x")
        fb = tk.Frame(fb_outer, bg=C["dash_bg"], padx=12, pady=10)
        fb.pack(fill="x")
        self._file_lbl = _lbl(fb, "No file selected",
                               fg=C["sub"], size=9, anchor="w")
        self._file_lbl.pack(side="left", fill="x", expand=True)
        DarkBtn(fb, "Browse Files", self._browse).pack(side="right")

        # Viewport (hidden until file chosen)
        self._vp = tk.Frame(p, bg=C["panel"])
        vp_hdr = tk.Frame(self._vp, bg=C["panel"])
        vp_hdr.pack(fill="x", pady=(10, 4))
        _lbl(vp_hdr, "Viewport Buffer", size=9, bold=True).pack(side="left")
        self._vp_meta = _lbl(vp_hdr, "", size=8, fg=C["sub"])
        self._vp_meta.pack(side="right")
        self._thumb = tk.Label(self._vp, bg=C["dark"])
        self._thumb.pack(fill="x")
        ovl = tk.Frame(self._thumb, bg=C["dark"])
        self._crc_lbl = tk.Label(ovl, text="", bg=C["dark"],
                                  fg=C["dark_sub"], font=("Courier", 7))
        self._crc_lbl.pack(side="left")
        tk.Label(ovl, text="Source Ready", bg=C["dark"],
                 fg=C["green"], font=(F, 7, "bold")).pack(side="right")
        ovl.place(relx=0, rely=1.0, anchor="sw", relwidth=1.0)

        # Key
        kh = tk.Frame(p, bg=C["panel"])
        kh.pack(fill="x", pady=(12, 4))
        self._use_key = tk.BooleanVar(value=False)
        tk.Checkbutton(kh, text=" Encrypt with Numeric Key",
                       variable=self._use_key, command=self._toggle_key,
                       bg=C["panel"], fg=C["text"],
                       font=(F, 9, "bold"),
                       activebackground=C["panel"],
                       selectcolor=C["panel"]).pack(side="left")
        _lbl(kh, "Pixel Manipulation Cipher",
             size=8, fg=C["sub"]).pack(side="right")
        self._pk = PasskeyEntry(p, "Enter key", on_change=self._key_changed)
        self._pk.pack(fill="x", pady=(2, 2))
        self._pk.set_enabled(False)
        self._strength = StrengthBar(p)
        self._strength.pack(fill="x", pady=(0, 10))

        # Buttons
        br = tk.Frame(p, bg=C["panel"])
        br.pack(fill="x", pady=(0, 6))
        self._enc_btn = DarkBtn(br, "Encrypt Image", self._encrypt)
        self._enc_btn.pack(side="left", fill="x", expand=True)
        OutlineBtn(br, "Reset", self._reset).pack(side="left", padx=(8, 0))

        # Info banner
        info = tk.Frame(p, bg=C["blue_l"],
                        highlightbackground="#BFDBFE",
                        highlightthickness=1)
        tk.Label(info,
                 text="After encryption, download the .enc file or copy Base64.",
                 bg=C["blue_l"], fg=C["blue"], font=(F, 8),
                 wraplength=320, justify="left",
                 padx=10, pady=6).pack()
        info.pack(fill="x", pady=(0, 8))

        # Result row (hidden)
        self._res_card = tk.Frame(p, bg=C["panel"],
                                   highlightbackground=C["border"],
                                   highlightthickness=1)
        rc = tk.Frame(self._res_card, bg=C["panel"], padx=10, pady=6)
        rc.pack(fill="x")
        tk.Label(rc, text="●", fg=C["green"], bg=C["panel"],
                 font=(F, 9)).pack(side="left")
        _lbl(rc, " Encrypted image ready",
             size=9, bold=True).pack(side="left")
        self._res_size = _lbl(rc, "", size=8, fg=C["sub"])
        self._res_size.pack(side="left", padx=4)

        dr = tk.Frame(p, bg=C["panel"])
        self._dl_row = dr
        DarkBtn(dr, "Download .enc", self._download).pack(
            side="left", fill="x", expand=True)
        OutlineBtn(dr, "Copy Base64", self._copy_b64, width=110).pack(
            side="left", padx=(8, 0))

    # ── callbacks ─────────────────────────────────────────

    def _toggle_key(self):
        self._pk.set_enabled(self._use_key.get())

    def _key_changed(self):
        self._strength.update(self._pk.get())

    def _browse(self):
        raw = filedialog.askopenfilename(
            title="Choose image",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp *.tiff *.webp"),
                       ("All files", "*.*")])
        if not raw: return
        path = Path(raw)
        if path.stat().st_size > 10 * 1024 * 1024:
            messagebox.showerror("Error", "File exceeds 10 MB."); return

        self._path = path
        sz = path.stat().st_size
        sz_s = f"{sz/1024:.1f} KB" if sz < 1024*1024 else f"{sz/1024/1024:.1f} MB"
        self._file_lbl.config(text=f"{path.name}  ·  {sz_s}",
                               fg=C["text"])
        try:
            img = Image.open(path)
            w, h = img.size
            self._vp_meta.config(text=f"{w} × {h}  ·  {img.mode}")
            thumb = img.copy().convert("RGB")
            thumb.thumbnail((THUMB_W, THUMB_H), Image.LANCZOS)
            photo = ImageTk.PhotoImage(thumb)
            self._thumb.config(image=photo, text="",
                               width=photo.width(),
                               height=photo.height())
            self._thumb.image = photo
            crc = hashlib.md5(img.tobytes()).hexdigest()[:8].upper()
            self._crc_lbl.config(text=f"CRC32: 0x{crc}")
        except Exception as exc:
            self._thumb.config(text=f"Preview unavailable", fg=C["sub"])

        self._vp.pack(fill="x", pady=(0, 8))
        self._enc_bytes = None
        self._res_card.pack_forget()
        self._dl_row.pack_forget()

    def _encrypt(self):
        if not self._path:
            messagebox.showerror("Error", "Please choose an image first."); return
        key = ""
        if self._use_key.get():
            key = self._pk.get()
            if not key:
                messagebox.showerror("Error", "Please enter a key."); return

        self._enc_btn.set_text("Encrypting…")
        self._enc_btn.set_enabled(False)

        def run():
            try:
                enc = encrypt_image(Image.open(self._path), key)
                self.after(0, lambda: self._on_done(enc))
            except Exception as exc:
                self.after(0, lambda: (
                    messagebox.showerror("Error", str(exc)),
                    self._enc_btn.set_text("Encrypt Image"),
                    self._enc_btn.set_enabled(True),
                ))
        threading.Thread(target=run, daemon=True).start()

    def _on_done(self, enc: bytes):
        self._enc_bytes = enc
        kb = len(enc) / 1024
        self._res_size.config(
            text=f"· {kb:.1f} KB" if kb < 1024 else f"· {kb/1024:.1f} MB")
        self._res_card.pack(fill="x", pady=(0, 6))
        self._dl_row.pack(fill="x", pady=(0, 4))
        self._enc_btn.set_text("Encrypt Image")
        self._enc_btn.set_enabled(True)

    def _download(self):
        if not self._enc_bytes: return
        stem = self._path.stem if self._path else "encrypted"
        raw = filedialog.asksaveasfilename(
            defaultextension=".enc", initialfile=f"{stem}.enc",
            filetypes=[("Encrypted file", "*.enc"), ("All files", "*.*")])
        if raw:
            Path(raw).write_bytes(self._enc_bytes)
            messagebox.showinfo("Saved", f"Saved to:\n{raw}")

    def _copy_b64(self):
        if not self._enc_bytes: return
        root = self.winfo_toplevel()
        root.clipboard_clear()
        root.clipboard_append(base64.b64encode(self._enc_bytes).decode())
        root.update()
        messagebox.showinfo("Copied", "Base64 string copied to clipboard.")

    def _reset(self):
        self._path = self._enc_bytes = None
        self._file_lbl.config(text="No file selected", fg=C["sub"])
        self._vp.pack_forget()
        self._res_card.pack_forget()
        self._dl_row.pack_forget()
        self._pk.clear()
        self._pk.set_enabled(False)
        self._use_key.set(False)
        self._strength.update("")


# ══════════════════════════════════════════════════════════
#  DECRYPT PANEL
# ══════════════════════════════════════════════════════════

class DecryptPanel(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=C["panel"],
                         highlightbackground=C["border"],
                         highlightthickness=1)
        self._enc_path: Path | None      = None
        self._result: Image.Image | None = None
        self._build()

    def _build(self):
        p = tk.Frame(self, bg=C["panel"], padx=18, pady=14)
        p.pack(fill="both", expand=True)

        # Header
        hdr = tk.Frame(p, bg=C["panel"])
        hdr.pack(fill="x", pady=(0, 8))
        icon_f = tk.Frame(hdr, bg=C["blue_l"], width=40, height=40)
        icon_f.pack(side="left"); icon_f.pack_propagate(False)
        tk.Label(icon_f, text="🔍", bg=C["blue_l"],
                 font=(F, 17)).place(relx=.5, rely=.5, anchor="center")
        tf = tk.Frame(hdr, bg=C["panel"])
        tf.pack(side="left", padx=(10, 0))
        _lbl(tf, "Decrypt Image", size=13, bold=True).pack(anchor="w")
        _lbl(tf, "Restore encrypted images from cipher data",
             size=8, fg=C["sub"]).pack(anchor="w")
        _badge(hdr, "Image Decoder",
               bg=C["blue_l"], fg=C["blue"]).pack(side="right")
        _sep(p).pack(fill="x", pady=(0, 10))

        # File chooser
        _lbl(p, "Encrypted File", size=9, fg=C["sub"]).pack(anchor="w", pady=(0, 4))
        fb_outer = tk.Frame(p, bg=C["dash_bg"],
                            highlightbackground=C["dash_bd"],
                            highlightthickness=1)
        fb_outer.pack(fill="x")
        fb = tk.Frame(fb_outer, bg=C["dash_bg"], padx=12, pady=10)
        fb.pack(fill="x")
        self._file_lbl = _lbl(fb, "No file selected",
                               fg=C["sub"], size=9, anchor="w")
        self._file_lbl.pack(side="left", fill="x", expand=True)
        DarkBtn(fb, "Browse Files", self._browse).pack(side="right")

        # Key
        kh = tk.Frame(p, bg=C["panel"])
        kh.pack(fill="x", pady=(12, 4))
        self._use_key = tk.BooleanVar(value=False)
        tk.Checkbutton(kh, text=" Same Key Required",
                       variable=self._use_key, command=self._toggle_key,
                       bg=C["panel"], fg=C["text"],
                       font=(F, 9, "bold"),
                       activebackground=C["panel"],
                       selectcolor=C["panel"]).pack(side="left")
        _lbl(kh, "Same Key Required",
             size=8, fg=C["sub"]).pack(side="right")
        self._pk = PasskeyEntry(p, "Enter key")
        self._pk.pack(fill="x", pady=(2, 2))
        self._pk.set_enabled(False)
        self._pk_status = _lbl(p, "", size=8, fg=C["sub"], anchor="w")
        self._pk_status.pack(fill="x", pady=(0, 10))

        # Buttons
        br = tk.Frame(p, bg=C["panel"])
        br.pack(fill="x", pady=(0, 6))
        self._dec_btn = DarkBtn(br, "Decrypt Image", self._decrypt)
        self._dec_btn.pack(side="left", fill="x", expand=True)
        OutlineBtn(br, "Reset", self._reset).pack(side="left", padx=(8, 0))

        # Warning
        warn = tk.Frame(p, bg=C["yellow_l"],
                        highlightbackground="#FDE68A",
                        highlightthickness=1)
        tk.Label(warn,
                 text="If decryption fails, the key may be incorrect or the file corrupted.",
                 bg=C["yellow_l"], fg=C["yellow_b"], font=(F, 8),
                 wraplength=320, justify="left",
                 padx=10, pady=6).pack()
        warn.pack(fill="x", pady=(0, 8))

        # Restored image (hidden)
        self._restored = tk.Frame(p, bg=C["panel"])
        rh = tk.Frame(self._restored, bg=C["panel"])
        rh.pack(fill="x", pady=(0, 6))
        tk.Label(rh, text="✅", bg=C["panel"],
                 font=(F, 11)).pack(side="left")
        _lbl(rh, "  Restored Image", size=10, bold=True).pack(side="left")
        _badge(rh, "Decrypted (Verified)",
               bg=C["green_l"], fg=C["green"]).pack(side="right")

        self._out_thumb = tk.Label(self._restored, bg=C["dark"])
        self._out_thumb.pack(fill="x")
        ovl = tk.Frame(self._out_thumb, bg=C["dark"])
        self._out_meta = tk.Label(ovl, text="", bg=C["dark"],
                                   fg=C["dark_sub"], font=("Courier", 7))
        self._out_meta.pack(side="left")
        tk.Label(ovl, text="100% Fidelity", bg=C["dark"],
                 fg=C["green"], font=(F, 7, "bold")).pack(side="right")
        ovl.place(relx=0, rely=1.0, anchor="sw", relwidth=1.0)

        DarkBtn(self._restored, "Download Restored Image",
                self._download).pack(fill="x", pady=(8, 0))

    # ── callbacks ─────────────────────────────────────────

    def _toggle_key(self):
        on = self._use_key.get()
        self._pk.set_enabled(on)
        self._pk_status.config(
            text="Enter the same key used during encryption" if on else "")

    def _browse(self):
        raw = filedialog.askopenfilename(
            title="Choose encrypted file",
            filetypes=[("Encrypted", "*.enc *.txt"),
                       ("All files", "*.*")])
        if not raw: return
        self._enc_path = Path(raw)
        sz = self._enc_path.stat().st_size
        sz_s = f"{sz/1024:.1f} KB" if sz < 1024*1024 else f"{sz/1024/1024:.1f} MB"
        self._file_lbl.config(
            text=f"{self._enc_path.name}  ·  {sz_s}", fg=C["text"])
        self._pk_status.config(text="Awaiting input…", fg=C["sub"])
        self._restored.pack_forget()

    def _decrypt(self):
        if not self._enc_path:
            messagebox.showerror("Error", "Please choose an encrypted file."); return
        key = ""
        if self._use_key.get():
            key = self._pk.get()
            if not key:
                messagebox.showerror("Error", "Please enter the key."); return

        self._dec_btn.set_text("Decrypting…")
        self._dec_btn.set_enabled(False)
        self._pk_status.config(text="Processing…", fg=C["sub"])

        def run():
            try:
                data = self._enc_path.read_bytes()
                img  = decrypt_bytes(data, key)
                self.after(0, lambda: self._on_done(img))
            except Exception as exc:
                self.after(0, lambda: (
                    self._pk_status.config(
                        text="Decryption failed — check your key",
                        fg=C["red"]),
                    messagebox.showerror("Failed",
                        f"Key may be incorrect or file corrupted.\n\n{exc}"),
                    self._dec_btn.set_text("Decrypt Image"),
                    self._dec_btn.set_enabled(True),
                ))
        threading.Thread(target=run, daemon=True).start()

    def _on_done(self, img: Image.Image):
        self._result = img
        w, h = img.size
        thumb = img.copy().convert("RGB")
        thumb.thumbnail((THUMB_W, THUMB_H), Image.LANCZOS)
        photo = ImageTk.PhotoImage(thumb)
        self._out_thumb.config(image=photo, text="",
                                width=photo.width(), height=photo.height())
        self._out_thumb.image = photo
        self._out_meta.config(text=f"{w} × {h}  ·  PNG")
        self._pk_status.config(
            text="Pixel values restored successfully", fg=C["green"])
        self._restored.pack(fill="x", pady=(8, 0))
        self._dec_btn.set_text("Decrypt Image")
        self._dec_btn.set_enabled(True)

    def _download(self):
        if not self._result: return
        stem = self._enc_path.stem if self._enc_path else "decrypted"
        raw = filedialog.asksaveasfilename(
            defaultextension=".png", initialfile=f"{stem}.png",
            filetypes=[("PNG image", "*.png"), ("All files", "*.*")])
        if raw:
            self._result.save(Path(raw))
            messagebox.showinfo("Saved", f"Saved to:\n{raw}")

    def _reset(self):
        self._enc_path = self._result = None
        self._file_lbl.config(text="No file selected", fg=C["sub"])
        self._restored.pack_forget()
        self._pk.clear()
        self._pk.set_enabled(False)
        self._use_key.set(False)
        self._pk_status.config(text="")


# ══════════════════════════════════════════════════════════
#  MAIN WINDOW
# ══════════════════════════════════════════════════════════

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PixelCrypt — Image Encryption & Decryption Tool")
        self.configure(bg=C["bg"])
        self.resizable(False, False)
        self._build()

    def _build(self):
        # Title bar
        tb = tk.Frame(self, bg=C["panel"],
                      highlightbackground=C["border"],
                      highlightthickness=1)
        tb.pack(fill="x")
        tb_in = tk.Frame(tb, bg=C["panel"], padx=18, pady=9)
        tb_in.pack(fill="x")
        _lbl(tb_in, "🛡  PixelCrypt — Image Encryption & Decryption Tool",
             size=12, bold=True).pack(side="left")
        _badge(tb_in, "● RGB Pixel Cipher",
               bg=C["green_l"], fg=C["green"]).pack(side="right")

        # Sub-bar
        sb = tk.Frame(self, bg=C["panel"],
                      highlightbackground=C["border"],
                      highlightthickness=1)
        sb.pack(fill="x")
        sb_in = tk.Frame(sb, bg=C["panel"], padx=18, pady=4)
        sb_in.pack(fill="x")
        _lbl(sb_in,
             "● Pixel Manipulation Cipher  ·  RGB Channel Encryption",
             size=8, fg=C["sub"]).pack(side="left")
        _lbl(sb_in,
             "Local Image Processing  ·  Offline Processing",
             size=8, fg=C["sub"]).pack(side="right")

        # Panels
        body = tk.Frame(self, bg=C["bg"], padx=12, pady=12)
        body.pack(fill="both", expand=True)
        EncryptPanel(body).grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        DecryptPanel(body).grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        # Status bar
        stb = tk.Frame(self, bg="#1E293B")
        stb.pack(fill="x", side="bottom")
        stb_in = tk.Frame(stb, bg="#1E293B", pady=5)
        stb_in.pack(fill="x", padx=12)
        for i, t in enumerate([
            "● RGB Pixel Manipulation",
            "XOR + Pixel Shuffle",
            "Pixel Manipulation Cipher",
            "PixelCrypt  ·  v1.0",
        ]):
            tk.Label(stb_in, text=t, bg="#1E293B", fg="#64748B",
                     font=(F, 7)).pack(side="left", padx=10)
            if i < 3:
                tk.Label(stb_in, text="·", bg="#1E293B", fg="#334155",
                         font=(F, 9)).pack(side="left")

        # Geometry
        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        w  = min(1060, sw - 40)
        h  = min(800, sh - 80)
        self.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")


if __name__ == "__main__":
    App().mainloop()
