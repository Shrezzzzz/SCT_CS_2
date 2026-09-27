"""
PixelCrypt — RGB Pixel Manipulation Image Encryption Tool
=========================================================
Run with:  python main.py

Cross-platform: macOS · Windows · Linux
Dependencies:   customtkinter, pillow, numpy
"""

from __future__ import annotations

import base64
import hashlib
import math
import random
import struct
import sys
import threading
from pathlib import Path

import customtkinter as ctk
import numpy as np
from PIL import Image, ImageTk
from tkinter import filedialog, messagebox

# ══════════════════════════════════════════════════════════
#  APPEARANCE
# ══════════════════════════════════════════════════════════
ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")

# ══════════════════════════════════════════════════════════
#  CRYPTO CORE  —  RGB Pixel Manipulation
# ══════════════════════════════════════════════════════════

def _derive_seed(key: str) -> int:
    """Derive a stable 32-bit seed from any string key via SHA-256."""
    return int(hashlib.sha256(key.encode()).hexdigest(), 16) % (2 ** 32)


def _shuffle_indices(total: int, seed: int) -> list[int]:
    idx = list(range(total))
    random.seed(seed)
    random.shuffle(idx)
    return idx


def encrypt_image(img: Image.Image, key: str) -> bytes:
    """
    RGB Pixel Manipulation Encryption:
      1. XOR each channel byte with (seed % 256)
      2. Shuffle pixel positions using seed as RNG seed
    Header: [4B width][4B height][4B mode_len][mode bytes]
    """
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGB")
    w, h   = img.size
    mode_b = img.mode.encode()
    pixels = np.array(img, dtype=np.uint8)
    seed   = _derive_seed(key)

    xored    = (pixels ^ (seed % 256)).astype(np.uint8)
    flat     = xored.reshape(-1, pixels.shape[2])
    shuffled = flat[_shuffle_indices(len(flat), seed)].flatten()
    return struct.pack(">III", w, h, len(mode_b)) + mode_b + shuffled.tobytes()


def decrypt_bytes(data: bytes, key: str) -> Image.Image:
    """Reverse the pixel manipulation to restore the original image."""
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


def clipboard_copy(root: ctk.CTk, text: str) -> None:
    """Cross-platform clipboard write."""
    root.clipboard_clear()
    root.clipboard_append(text)
    root.update()


# ══════════════════════════════════════════════════════════
#  COLOUR PALETTE
# ══════════════════════════════════════════════════════════
C = {
    "bg":        "#F0F2F5",
    "panel":     "#FFFFFF",
    "border":    "#DDE1E7",
    "border2":   "#C8CDD6",
    "text":      "#1A1D23",
    "sub":       "#6B7280",
    "btn":       "#1E293B",
    "btn_hv":    "#334155",
    "btn_dis":   "#94A3B8",
    "green":     "#16A34A",
    "green_l":   "#DCFCE7",
    "blue":      "#2563EB",
    "blue_l":    "#EFF6FF",
    "yellow_l":  "#FEFCE8",
    "yellow_b":  "#CA8A04",
    "red":       "#DC2626",
    "dash_bg":   "#F8FAFC",
    "dash_bd":   "#CBD5E1",
    "badge_bg":  "#F1F5F9",
    "badge_fg":  "#475569",
    "dark":      "#0F172A",
    "dark_sub":  "#64748B",
}

THUMB_W, THUMB_H = 380, 160
FONT_FAMILY = "Inter"          # falls back gracefully on all platforms


# ══════════════════════════════════════════════════════════
#  REUSABLE CTK WIDGETS
# ══════════════════════════════════════════════════════════

class DarkButton(ctk.CTkButton):
    """Consistent dark charcoal button used everywhere."""
    def __init__(self, master, text, command, **kw):
        super().__init__(
            master,
            text=text,
            command=command,
            fg_color=C["btn"],
            hover_color=C["btn_hv"],
            text_color="#FFFFFF",
            corner_radius=6,
            height=36,
            font=(FONT_FAMILY, 12, "bold"),
            **kw,
        )


class OutlineButton(ctk.CTkButton):
    def __init__(self, master, text, command, **kw):
        super().__init__(
            master,
            text=text,
            command=command,
            fg_color="transparent",
            hover_color=C["bg"],
            text_color=C["text"],
            border_color=C["border2"],
            border_width=1,
            corner_radius=6,
            height=36,
            font=(FONT_FAMILY, 11),
            **kw,
        )


class SectionLabel(ctk.CTkLabel):
    def __init__(self, master, text, **kw):
        super().__init__(
            master,
            text=text,
            text_color=C["sub"],
            font=(FONT_FAMILY, 9),
            **kw,
        )


class BadgeLabel(ctk.CTkLabel):
    def __init__(self, master, text, bg=None, fg=None, **kw):
        super().__init__(
            master,
            text=text,
            fg_color=bg or C["badge_bg"],
            text_color=fg or C["badge_fg"],
            corner_radius=4,
            font=(FONT_FAMILY, 8, "bold"),
            **kw,
        )


class PasskeyEntry(ctk.CTkFrame):
    """Password entry with show/hide toggle and placeholder."""

    def __init__(self, master, placeholder: str = "Enter key", on_change=None):
        super().__init__(master, fg_color=C["panel"],
                         border_color=C["border2"], border_width=1,
                         corner_radius=6)
        self._ph      = placeholder
        self._is_ph   = True
        self._visible = False
        self._cb      = on_change

        self._key_icon = ctk.CTkLabel(self, text="🔑", width=24,
                                      font=(FONT_FAMILY, 12))
        self._key_icon.pack(side="left", padx=(10, 0), pady=6)

        self._var   = ctk.StringVar(value=placeholder)
        self._entry = ctk.CTkEntry(
            self, textvariable=self._var,
            placeholder_text="",
            fg_color="transparent",
            border_width=0,
            text_color=C["sub"],
            font=(FONT_FAMILY, 11),
            show="",
        )
        self._entry.pack(side="left", fill="x", expand=True, pady=6)
        self._entry.bind("<FocusIn>",  self._focus_in)
        self._entry.bind("<FocusOut>", self._focus_out)
        if on_change:
            self._var.trace_add("write", lambda *_: on_change())

        self._eye = ctk.CTkButton(
            self, text="👁", width=30, fg_color="transparent",
            hover_color=C["bg"], text_color=C["sub"],
            font=(FONT_FAMILY, 13), command=self._toggle,
        )
        self._eye.pack(side="right", padx=(0, 6), pady=4)

    def _focus_in(self, _):
        if self._is_ph:
            self._entry.delete(0, "end")
            self._entry.configure(text_color=C["text"], show="•")
            self._is_ph = False

    def _focus_out(self, _):
        if self._entry.get() == "":
            self._entry.configure(show="", text_color=C["sub"])
            self._entry.insert(0, self._ph)
            self._is_ph = True

    def _toggle(self):
        if self._is_ph:
            return
        self._visible = not self._visible
        self._entry.configure(show="" if self._visible else "•")

    def get(self) -> str:
        return "" if self._is_ph else self._entry.get()

    def set_enabled(self, on: bool):
        state = "normal" if on else "disabled"
        self._entry.configure(state=state)
        self._eye.configure(state=state)

    def clear(self):
        self._entry.configure(state="normal", show="", text_color=C["sub"])
        self._entry.delete(0, "end")
        self._entry.insert(0, self._ph)
        self._is_ph   = True
        self._visible = False


class StrengthBar(ctk.CTkFrame):
    """5-segment key strength bar."""

    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        bar_row = ctk.CTkFrame(self, fg_color="transparent")
        bar_row.pack(fill="x")
        self._segs: list[ctk.CTkFrame] = []
        for _ in range(5):
            s = ctk.CTkFrame(bar_row, height=5, corner_radius=2,
                             fg_color="#E5E7EB")
            s.pack(side="left", fill="x", expand=True, padx=1)
            self._segs.append(s)
        self._lbl = ctk.CTkLabel(self, text="", text_color=C["sub"],
                                  font=(FONT_FAMILY, 8), anchor="e")
        self._lbl.pack(fill="x")

    def update_key(self, key: str):
        bits  = key_entropy_bits(key)
        score = min(int(bits / 1.28), 100)
        levels = [
            (20, C["red"],     "Weak"),
            (40, "#F59E0B",    "Fair"),
            (60, "#84CC16",    "Good"),
            (80, C["green"],   "Strong"),
            (100, C["green"],  "Strong"),
        ]
        filled, color, label = 0, "#E5E7EB", ""
        for thresh, c, l in levels:
            if score >= thresh:
                filled += 1; color = c; label = l
        for i, seg in enumerate(self._segs):
            seg.configure(fg_color=color if i < filled else "#E5E7EB")
        txt = f"Strength: {label}  ({bits}-bit)" if label else ""
        self._lbl.configure(text=txt,
                            text_color=color if label else C["sub"])


# ══════════════════════════════════════════════════════════
#  ENCRYPT PANEL
# ══════════════════════════════════════════════════════════

class EncryptPanel(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color=C["panel"],
                         corner_radius=10, border_color=C["border"],
                         border_width=1)
        self._path: Path | None      = None
        self._enc_bytes: bytes | None = None
        self._root: ctk.CTk | None   = None   # set after build
        self._build()

    def _build(self):
        p = ctk.CTkFrame(self, fg_color="transparent")
        p.pack(fill="both", expand=True, padx=18, pady=14)

        # ── Header ───────────────────────────────────────
        hdr = ctk.CTkFrame(p, fg_color="transparent")
        hdr.pack(fill="x", pady=(0, 8))

        icon_bg = ctk.CTkFrame(hdr, fg_color="#FFF3ED",
                               corner_radius=8, width=40, height=40)
        icon_bg.pack(side="left"); icon_bg.pack_propagate(False)
        ctk.CTkLabel(icon_bg, text="🛡", font=(FONT_FAMILY, 18)).place(
            relx=.5, rely=.5, anchor="center")

        txt = ctk.CTkFrame(hdr, fg_color="transparent")
        txt.pack(side="left", padx=(10, 0))
        ctk.CTkLabel(txt, text="Encrypt Image",
                     font=(FONT_FAMILY, 14, "bold"),
                     text_color=C["text"]).pack(anchor="w")
        ctk.CTkLabel(txt, text="Pixel manipulation encryption",
                     font=(FONT_FAMILY, 9), text_color=C["sub"]).pack(anchor="w")

        BadgeLabel(hdr, "RGB Pixel Cipher").pack(side="right")

        ctk.CTkFrame(p, height=1, fg_color=C["border"]).pack(fill="x", pady=(0, 10))

        # ── File chooser ─────────────────────────────────
        SectionLabel(p, "Source Image").pack(anchor="w", pady=(0, 4))

        file_box = ctk.CTkFrame(p, fg_color=C["dash_bg"],
                                corner_radius=6, border_color=C["dash_bd"],
                                border_width=1)
        file_box.pack(fill="x")
        fb = ctk.CTkFrame(file_box, fg_color="transparent")
        fb.pack(fill="x", padx=12, pady=10)

        self._file_lbl = ctk.CTkLabel(
            fb, text="No file selected",
            text_color=C["sub"], font=(FONT_FAMILY, 9), anchor="w")
        self._file_lbl.pack(side="left", fill="x", expand=True)
        DarkButton(fb, "Browse Files", self._browse, width=110).pack(side="right")

        # ── Viewport (hidden until loaded) ───────────────
        self._vp = ctk.CTkFrame(p, fg_color="transparent")

        vp_hdr = ctk.CTkFrame(self._vp, fg_color="transparent")
        vp_hdr.pack(fill="x", pady=(10, 4))
        ctk.CTkLabel(vp_hdr, text="Viewport Buffer",
                     font=(FONT_FAMILY, 9, "bold"),
                     text_color=C["text"]).pack(side="left")
        self._vp_meta = ctk.CTkLabel(vp_hdr, text="",
                                      font=(FONT_FAMILY, 8),
                                      text_color=C["sub"])
        self._vp_meta.pack(side="right")

        self._thumb_lbl = ctk.CTkLabel(self._vp, text="",
                                        fg_color=C["dark"],
                                        corner_radius=6)
        self._thumb_lbl.pack(fill="x")

        ovl = ctk.CTkFrame(self._thumb_lbl, fg_color="transparent")
        self._crc_lbl = ctk.CTkLabel(ovl, text="", text_color=C["dark_sub"],
                                      font=("Courier", 7))
        self._crc_lbl.pack(side="left")
        ctk.CTkLabel(ovl, text="Source Ready",
                     text_color=C["green"],
                     font=(FONT_FAMILY, 7, "bold")).pack(side="right")
        ovl.place(relx=0, rely=1.0, anchor="sw", relwidth=1.0)

        # ── Key / passkey ────────────────────────────────
        kh = ctk.CTkFrame(p, fg_color="transparent")
        kh.pack(fill="x", pady=(12, 4))

        self._use_key = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(kh, text=" Encrypt with Numeric Key",
                        variable=self._use_key,
                        command=self._toggle_key,
                        font=(FONT_FAMILY, 10, "bold"),
                        text_color=C["text"],
                        fg_color=C["btn"],
                        hover_color=C["btn_hv"],
                        checkmark_color="#FFFFFF").pack(side="left")
        ctk.CTkLabel(kh, text="Pixel Manipulation Cipher",
                     font=(FONT_FAMILY, 8), text_color=C["sub"]).pack(side="right")

        self._pk = PasskeyEntry(p, "Enter key", on_change=self._key_changed)
        self._pk.pack(fill="x", pady=(2, 2))
        self._pk.set_enabled(False)

        self._strength = StrengthBar(p)
        self._strength.pack(fill="x", pady=(0, 10))

        # ── Action buttons ───────────────────────────────
        br = ctk.CTkFrame(p, fg_color="transparent")
        br.pack(fill="x", pady=(0, 6))
        self._enc_btn = DarkButton(br, "Encrypt Image", self._encrypt)
        self._enc_btn.pack(side="left", fill="x", expand=True)
        OutlineButton(br, "Reset", self._reset, width=90).pack(
            side="left", padx=(8, 0))

        # ── Info banner ──────────────────────────────────
        info = ctk.CTkFrame(p, fg_color=C["blue_l"],
                            corner_radius=6, border_color="#BFDBFE",
                            border_width=1)
        ctk.CTkLabel(info,
                     text="After encryption, download the .enc file or copy Base64.",
                     text_color=C["blue"], font=(FONT_FAMILY, 8),
                     wraplength=320, justify="left").pack(padx=10, pady=6)
        info.pack(fill="x", pady=(0, 8))

        # ── Result row (hidden) ──────────────────────────
        self._res_card = ctk.CTkFrame(p, fg_color=C["panel"],
                                      corner_radius=6,
                                      border_color=C["border"],
                                      border_width=1)
        rc = ctk.CTkFrame(self._res_card, fg_color="transparent")
        rc.pack(fill="x", padx=10, pady=6)
        ctk.CTkLabel(rc, text="●", text_color=C["green"],
                     font=(FONT_FAMILY, 10)).pack(side="left")
        ctk.CTkLabel(rc, text=" Encrypted image ready",
                     font=(FONT_FAMILY, 9, "bold"),
                     text_color=C["text"]).pack(side="left")
        self._res_size = ctk.CTkLabel(rc, text="",
                                       font=(FONT_FAMILY, 8),
                                       text_color=C["sub"])
        self._res_size.pack(side="left", padx=4)

        dr = ctk.CTkFrame(p, fg_color="transparent")
        self._dl_row = dr
        DarkButton(dr, "Download .enc", self._download).pack(
            side="left", fill="x", expand=True)
        OutlineButton(dr, "Copy Base64", self._copy_b64, width=110).pack(
            side="left", padx=(8, 0))

    # ── Callbacks ─────────────────────────────────────────

    def _toggle_key(self):
        self._pk.set_enabled(self._use_key.get())

    def _key_changed(self):
        self._strength.update_key(self._pk.get())

    def _browse(self):
        raw = filedialog.askopenfilename(
            title="Choose image",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp *.tiff *.webp"),
                       ("All files", "*.*")])
        if not raw:
            return
        path = Path(raw)
        if path.stat().st_size > 10 * 1024 * 1024:
            messagebox.showerror("Error", "File exceeds 10 MB limit.")
            return

        self._path = path
        sz = path.stat().st_size
        sz_str = f"{sz/1024:.1f} KB" if sz < 1024*1024 else f"{sz/1024/1024:.1f} MB"
        self._file_lbl.configure(text=f"{path.name}  ·  {sz_str}",
                                  text_color=C["text"])
        try:
            img = Image.open(path)
            w, h = img.size
            self._vp_meta.configure(text=f"{w} × {h}  ·  {img.mode}")
            thumb = img.copy().convert("RGB")
            thumb.thumbnail((THUMB_W, THUMB_H), Image.LANCZOS)
            photo = ImageTk.PhotoImage(thumb)
            self._thumb_lbl.configure(
                image=photo,
                width=photo.width(),
                height=photo.height(),
            )
            self._thumb_lbl.image = photo          # keep reference
            crc = hashlib.md5(img.tobytes()).hexdigest()[:8].upper()
            self._crc_lbl.configure(text=f"CRC32: 0x{crc}")
        except Exception as exc:
            self._thumb_lbl.configure(text=f"Preview unavailable: {exc}")

        self._vp.pack(fill="x", pady=(0, 8))
        self._enc_bytes = None
        self._res_card.pack_forget()
        self._dl_row.pack_forget()

    def _encrypt(self):
        if not self._path:
            messagebox.showerror("Error", "Please choose an image first.")
            return
        key = ""
        if self._use_key.get():
            key = self._pk.get()
            if not key:
                messagebox.showerror("Error", "Please enter a numeric key.")
                return

        self._enc_btn.configure(text="Encrypting…", state="disabled")

        def run():
            try:
                enc = encrypt_image(Image.open(self._path), key)
                self.after(0, lambda: self._on_done(enc))
            except Exception as exc:
                self.after(0, lambda: (
                    messagebox.showerror("Error", str(exc)),
                    self._enc_btn.configure(text="Encrypt Image", state="normal"),
                ))
        threading.Thread(target=run, daemon=True).start()

    def _on_done(self, enc: bytes):
        self._enc_bytes = enc
        kb = len(enc) / 1024
        self._res_size.configure(
            text=f"· {kb:.1f} KB" if kb < 1024 else f"· {kb/1024:.1f} MB")
        self._res_card.pack(fill="x", pady=(0, 6))
        self._dl_row.pack(fill="x", pady=(0, 4))
        self._enc_btn.configure(text="Encrypt Image", state="normal")

    def _download(self):
        if not self._enc_bytes:
            return
        stem = self._path.stem if self._path else "encrypted"
        raw = filedialog.asksaveasfilename(
            defaultextension=".enc",
            initialfile=f"{stem}.enc",
            filetypes=[("Encrypted file", "*.enc"), ("All files", "*.*")])
        if raw:
            Path(raw).write_bytes(self._enc_bytes)
            messagebox.showinfo("Saved", f"Saved to:\n{raw}")

    def _copy_b64(self):
        if not self._enc_bytes:
            return
        clipboard_copy(self.winfo_toplevel(),
                       base64.b64encode(self._enc_bytes).decode())
        messagebox.showinfo("Copied", "Base64 string copied to clipboard.")

    def _reset(self):
        self._path = self._enc_bytes = None
        self._file_lbl.configure(text="No file selected",
                                  text_color=C["sub"])
        self._vp.pack_forget()
        self._res_card.pack_forget()
        self._dl_row.pack_forget()
        self._pk.clear()
        self._pk.set_enabled(False)
        self._use_key.set(False)
        self._strength.update_key("")


# ══════════════════════════════════════════════════════════
#  DECRYPT PANEL
# ══════════════════════════════════════════════════════════

class DecryptPanel(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color=C["panel"],
                         corner_radius=10, border_color=C["border"],
                         border_width=1)
        self._enc_path: Path | None       = None
        self._result: Image.Image | None  = None
        self._build()

    def _build(self):
        p = ctk.CTkFrame(self, fg_color="transparent")
        p.pack(fill="both", expand=True, padx=18, pady=14)

        # ── Header ───────────────────────────────────────
        hdr = ctk.CTkFrame(p, fg_color="transparent")
        hdr.pack(fill="x", pady=(0, 8))

        icon_bg = ctk.CTkFrame(hdr, fg_color=C["blue_l"],
                               corner_radius=8, width=40, height=40)
        icon_bg.pack(side="left"); icon_bg.pack_propagate(False)
        ctk.CTkLabel(icon_bg, text="🔍", font=(FONT_FAMILY, 18)).place(
            relx=.5, rely=.5, anchor="center")

        txt = ctk.CTkFrame(hdr, fg_color="transparent")
        txt.pack(side="left", padx=(10, 0))
        ctk.CTkLabel(txt, text="Decrypt Image",
                     font=(FONT_FAMILY, 14, "bold"),
                     text_color=C["text"]).pack(anchor="w")
        ctk.CTkLabel(txt, text="Restore encrypted images from cipher data",
                     font=(FONT_FAMILY, 9), text_color=C["sub"]).pack(anchor="w")

        BadgeLabel(hdr, "Image Decoder", bg=C["blue_l"], fg=C["blue"]).pack(
            side="right")

        ctk.CTkFrame(p, height=1, fg_color=C["border"]).pack(fill="x", pady=(0, 10))

        # ── File chooser ─────────────────────────────────
        SectionLabel(p, "Encrypted File").pack(anchor="w", pady=(0, 4))

        file_box = ctk.CTkFrame(p, fg_color=C["dash_bg"],
                                corner_radius=6, border_color=C["dash_bd"],
                                border_width=1)
        file_box.pack(fill="x")
        fb = ctk.CTkFrame(file_box, fg_color="transparent")
        fb.pack(fill="x", padx=12, pady=10)
        self._file_lbl = ctk.CTkLabel(
            fb, text="No file selected",
            text_color=C["sub"], font=(FONT_FAMILY, 9), anchor="w")
        self._file_lbl.pack(side="left", fill="x", expand=True)
        DarkButton(fb, "Browse Files", self._browse, width=110).pack(side="right")

        # ── Key ──────────────────────────────────────────
        kh = ctk.CTkFrame(p, fg_color="transparent")
        kh.pack(fill="x", pady=(12, 4))
        self._use_key = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(kh, text=" Same Key Required",
                        variable=self._use_key,
                        command=self._toggle_key,
                        font=(FONT_FAMILY, 10, "bold"),
                        text_color=C["text"],
                        fg_color=C["btn"],
                        hover_color=C["btn_hv"],
                        checkmark_color="#FFFFFF").pack(side="left")
        ctk.CTkLabel(kh, text="Same Key Required",
                     font=(FONT_FAMILY, 8), text_color=C["sub"]).pack(side="right")

        self._pk = PasskeyEntry(p, "Enter key")
        self._pk.pack(fill="x", pady=(2, 2))
        self._pk.set_enabled(False)

        self._pk_status = ctk.CTkLabel(p, text="",
                                        font=(FONT_FAMILY, 8),
                                        text_color=C["sub"],
                                        anchor="w")
        self._pk_status.pack(fill="x", pady=(0, 10))

        # ── Action buttons ───────────────────────────────
        br = ctk.CTkFrame(p, fg_color="transparent")
        br.pack(fill="x", pady=(0, 6))
        self._dec_btn = DarkButton(br, "Decrypt Image", self._decrypt)
        self._dec_btn.pack(side="left", fill="x", expand=True)
        OutlineButton(br, "Reset", self._reset, width=90).pack(
            side="left", padx=(8, 0))

        # ── Warning banner ───────────────────────────────
        warn = ctk.CTkFrame(p, fg_color=C["yellow_l"],
                            corner_radius=6, border_color="#FDE68A",
                            border_width=1)
        ctk.CTkLabel(warn,
                     text="If decryption fails, the key may be incorrect or the file may be corrupted.",
                     text_color=C["yellow_b"], font=(FONT_FAMILY, 8),
                     wraplength=320, justify="left").pack(padx=10, pady=6)
        warn.pack(fill="x", pady=(0, 8))

        # ── Restored image (hidden) ──────────────────────
        self._restored = ctk.CTkFrame(p, fg_color="transparent")

        rh = ctk.CTkFrame(self._restored, fg_color="transparent")
        rh.pack(fill="x", pady=(0, 6))
        ctk.CTkLabel(rh, text="✅", font=(FONT_FAMILY, 12)).pack(side="left")
        ctk.CTkLabel(rh, text="  Restored Image",
                     font=(FONT_FAMILY, 11, "bold"),
                     text_color=C["text"]).pack(side="left")
        BadgeLabel(rh, "Decrypted (Verified)",
                   bg=C["green_l"], fg=C["green"]).pack(side="right")

        self._out_thumb = ctk.CTkLabel(self._restored, text="",
                                        fg_color=C["dark"],
                                        corner_radius=6)
        self._out_thumb.pack(fill="x")

        ovl = ctk.CTkFrame(self._out_thumb, fg_color="transparent")
        self._out_meta = ctk.CTkLabel(ovl, text="",
                                       text_color=C["dark_sub"],
                                       font=("Courier", 7))
        self._out_meta.pack(side="left")
        ctk.CTkLabel(ovl, text="100% Fidelity",
                     text_color=C["green"],
                     font=(FONT_FAMILY, 7, "bold")).pack(side="right")
        ovl.place(relx=0, rely=1.0, anchor="sw", relwidth=1.0)

        DarkButton(self._restored, "Download Restored Image",
                   self._download).pack(fill="x", pady=(8, 0))

    # ── Callbacks ─────────────────────────────────────────

    def _toggle_key(self):
        on = self._use_key.get()
        self._pk.set_enabled(on)
        self._pk_status.configure(
            text="Enter the same key used during encryption" if on else "")

    def _browse(self):
        raw = filedialog.askopenfilename(
            title="Choose encrypted file",
            filetypes=[("Encrypted", "*.enc *.txt"),
                       ("All files", "*.*")])
        if not raw:
            return
        self._enc_path = Path(raw)
        sz = self._enc_path.stat().st_size
        sz_str = f"{sz/1024:.1f} KB" if sz < 1024*1024 else f"{sz/1024/1024:.1f} MB"
        self._file_lbl.configure(
            text=f"{self._enc_path.name}  ·  {sz_str}",
            text_color=C["text"])
        self._pk_status.configure(text="Awaiting input…",
                                   text_color=C["sub"])
        self._restored.pack_forget()

    def _decrypt(self):
        if not self._enc_path:
            messagebox.showerror("Error", "Please choose an encrypted file.")
            return
        key = ""
        if self._use_key.get():
            key = self._pk.get()
            if not key:
                messagebox.showerror("Error", "Please enter the key.")
                return

        self._dec_btn.configure(text="Decrypting…", state="disabled")
        self._pk_status.configure(text="Processing…", text_color=C["sub"])

        def run():
            try:
                data = self._enc_path.read_bytes()
                img  = decrypt_bytes(data, key)
                self.after(0, lambda: self._on_done(img))
            except Exception as exc:
                self.after(0, lambda: (
                    self._pk_status.configure(
                        text="Decryption failed — check your key",
                        text_color=C["red"]),
                    messagebox.showerror("Failed",
                        f"Key may be incorrect or file corrupted.\n\n{exc}"),
                    self._dec_btn.configure(
                        text="Decrypt Image", state="normal"),
                ))
        threading.Thread(target=run, daemon=True).start()

    def _on_done(self, img: Image.Image):
        self._result = img
        w, h = img.size
        thumb = img.copy().convert("RGB")
        thumb.thumbnail((THUMB_W, THUMB_H), Image.LANCZOS)
        photo = ImageTk.PhotoImage(thumb)
        self._out_thumb.configure(
            image=photo,
            width=photo.width(),
            height=photo.height(),
        )
        self._out_thumb.image = photo
        self._out_meta.configure(text=f"{w} × {h}  ·  PNG")
        self._pk_status.configure(
            text="Pixel values restored successfully",
            text_color=C["green"])
        self._restored.pack(fill="x", pady=(8, 0))
        self._dec_btn.configure(text="Decrypt Image", state="normal")

    def _download(self):
        if not self._result:
            return
        stem = self._enc_path.stem if self._enc_path else "decrypted"
        raw = filedialog.asksaveasfilename(
            defaultextension=".png",
            initialfile=f"{stem}.png",
            filetypes=[("PNG image", "*.png"), ("All files", "*.*")])
        if raw:
            self._result.save(Path(raw))
            messagebox.showinfo("Saved", f"Saved to:\n{raw}")

    def _reset(self):
        self._enc_path = self._result = None
        self._file_lbl.configure(text="No file selected",
                                  text_color=C["sub"])
        self._restored.pack_forget()
        self._pk.clear()
        self._pk.set_enabled(False)
        self._use_key.set(False)
        self._pk_status.configure(text="")


# ══════════════════════════════════════════════════════════
#  MAIN WINDOW
# ══════════════════════════════════════════════════════════

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("PixelCrypt — Image Encryption & Decryption Tool")
        self.configure(fg_color=C["bg"])
        self.resizable(False, False)

        self._build_titlebar()
        self._build_subbar()
        self._build_panels()
        self._build_statusbar()

        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        w  = min(1080, sw - 40)
        h  = min(800, sh - 80)
        self.geometry(f"{w}x{h}+{(sw - w)//2}+{(sh - h)//2}")

    def _build_titlebar(self):
        tb = ctk.CTkFrame(self, fg_color=C["panel"],
                          corner_radius=0, border_color=C["border"],
                          border_width=1)
        tb.pack(fill="x")
        inner = ctk.CTkFrame(tb, fg_color="transparent")
        inner.pack(fill="x", padx=18, pady=9)
        ctk.CTkLabel(inner,
                     text="🛡  PixelCrypt — Image Encryption & Decryption Tool",
                     font=(FONT_FAMILY, 13, "bold"),
                     text_color=C["text"]).pack(side="left")
        BadgeLabel(inner, "● RGB Pixel Cipher",
                   bg=C["green_l"], fg=C["green"]).pack(side="right")

    def _build_subbar(self):
        sb = ctk.CTkFrame(self, fg_color=C["panel"],
                          corner_radius=0, border_color=C["border"],
                          border_width=1)
        sb.pack(fill="x")
        inner = ctk.CTkFrame(sb, fg_color="transparent")
        inner.pack(fill="x", padx=18, pady=4)
        ctk.CTkLabel(inner,
                     text="● Pixel Manipulation Cipher  ·  RGB Channel Encryption",
                     font=(FONT_FAMILY, 8), text_color=C["sub"]).pack(side="left")
        ctk.CTkLabel(inner,
                     text="Local Image Processing  ·  Offline Processing",
                     font=(FONT_FAMILY, 8), text_color=C["sub"]).pack(side="right")

    def _build_panels(self):
        body = ctk.CTkFrame(self, fg_color=C["bg"])
        body.pack(fill="both", expand=True, padx=12, pady=12)

        enc = EncryptPanel(body)
        enc.grid(row=0, column=0, sticky="nsew", padx=(0, 6))

        dec = DecryptPanel(body)
        dec.grid(row=0, column=1, sticky="nsew", padx=(6, 0))

        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

    def _build_statusbar(self):
        stb = ctk.CTkFrame(self, fg_color="#1E293B",
                           corner_radius=0, height=28)
        stb.pack(fill="x", side="bottom")
        stb.pack_propagate(False)

        items = [
            "● RGB Pixel Manipulation",
            "XOR + Pixel Shuffle",
            "Pixel Manipulation Cipher",
            "PixelCrypt  ·  v1.0",
        ]
        inner = ctk.CTkFrame(stb, fg_color="transparent")
        inner.pack(fill="x", padx=12, pady=4)
        for i, t in enumerate(items):
            ctk.CTkLabel(inner, text=t, font=(FONT_FAMILY, 7),
                         text_color="#64748B").pack(side="left", padx=10)
            if i < len(items) - 1:
                ctk.CTkLabel(inner, text="·", font=(FONT_FAMILY, 9),
                             text_color="#334155").pack(side="left")


# ══════════════════════════════════════════════════════════
if __name__ == "__main__":
    app = App()
    app.mainloop()
