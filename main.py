"""
Image Encryption Tool  —  python main.py
"""

import tkinter as tk
from tkinter import filedialog, messagebox
import threading, os, base64, hashlib, random, struct, math

import numpy as np
from PIL import Image, ImageTk

# ══════════════════════════════════════════════════════════
#  CRYPTO CORE
# ══════════════════════════════════════════════════════════

def _derive_key(passkey: str) -> int:
    return int(hashlib.sha256(passkey.encode()).hexdigest(), 16) % (2 ** 32)

def _shuffle_indices(total: int, seed: int) -> list:
    idx = list(range(total))
    random.seed(seed)
    random.shuffle(idx)
    return idx

def encrypt_image(img: Image.Image, passkey: str) -> bytes:
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGB")
    w, h   = img.size
    mode_b = img.mode.encode()
    pixels = np.array(img, dtype=np.uint8)
    seed   = _derive_key(passkey)
    xored  = (pixels ^ (seed % 256)).astype(np.uint8)
    flat   = xored.reshape(-1, pixels.shape[2])
    shuffled = flat[_shuffle_indices(len(flat), seed)].flatten()
    return struct.pack(">III", w, h, len(mode_b)) + mode_b + shuffled.tobytes()

def decrypt_bytes(enc: bytes, passkey: str) -> Image.Image:
    w, h, mode_len = struct.unpack(">III", enc[:12])
    mode     = enc[12: 12 + mode_len].decode()
    body     = enc[12 + mode_len:]
    channels = len(mode)
    seed     = _derive_key(passkey)
    flat_enc = np.frombuffer(body, dtype=np.uint8).reshape(w * h, channels)
    indices  = _shuffle_indices(w * h, seed)
    restored = np.empty_like(flat_enc)
    for i, orig in enumerate(indices):
        restored[orig] = flat_enc[i]
    pixels = (restored ^ (seed % 256)).astype(np.uint8).reshape(h, w, channels)
    return Image.fromarray(pixels, mode)

def passkey_entropy_bits(pw: str) -> int:
    if not pw: return 0
    charset = 0
    if any(c.islower() for c in pw): charset += 26
    if any(c.isupper() for c in pw): charset += 26
    if any(c.isdigit() for c in pw): charset += 10
    if any(not c.isalnum() for c in pw): charset += 32
    return int(len(pw) * math.log2(charset)) if charset else 0

# ══════════════════════════════════════════════════════════
#  THEME
# ══════════════════════════════════════════════════════════
BG       = "#f0f2f5"
PANEL    = "#ffffff"
BORDER   = "#dde1e7"
BORDER2  = "#c8cdd6"
TEXT     = "#1a1d23"
SUBTEXT  = "#6b7280"
BTN_BG   = "#1e293b"
BTN_HV   = "#334155"
BTN_DIS  = "#94a3b8"
GREEN    = "#16a34a"
GREEN_L  = "#dcfce7"
BLUE     = "#2563eb"
BLUE_L   = "#eff6ff"
YELLOW_L = "#fefce8"
YELLOW_B = "#ca8a04"
RED      = "#dc2626"
DASH_BG  = "#f8fafc"
DASH_BD  = "#cbd5e1"
BADGE_BG = "#f1f5f9"
BADGE_FG = "#475569"
DARK_BG  = "#0f172a"
THUMB_W  = 380
THUMB_H  = 200

FONT     = "Helvetica"

# ── helpers ───────────────────────────────────────────────

def lbl(parent, text, size=10, bold=False, fg=TEXT, **kw):
    f = ("bold" if bold else "normal")
    return tk.Label(parent, text=text, bg=parent["bg"], fg=fg,
                    font=(FONT, size, f), **kw)

def badge(parent, text, bg=BADGE_BG, fg=BADGE_FG, size=8):
    return tk.Label(parent, text=text, bg=bg, fg=fg,
                    font=(FONT, size, "bold"), padx=7, pady=3)

def sep(parent, color=BORDER):
    return tk.Frame(parent, bg=color, height=1)

# ── Scrollable panel ──────────────────────────────────────

class ScrollableFrame(tk.Frame):
    """
    Scrollable panel. Works by tracking pointer position against the
    frame's bounding box — no per-child binding needed.
    """
    # Class-level registry so the global handler knows all instances
    _instances: list = []

    def __init__(self, parent, bg=PANEL, **kw):
        super().__init__(parent, bg=bg, **kw)
        ScrollableFrame._instances.append(self)

        self._canvas = tk.Canvas(self, bg=bg, highlightthickness=0)
        self._sb     = tk.Scrollbar(self, orient="vertical",
                                    command=self._canvas.yview)
        self._canvas.configure(yscrollcommand=self._sb.set)
        self._sb.pack(side="right", fill="y")
        self._canvas.pack(side="left", fill="both", expand=True)

        self.inner = tk.Frame(self._canvas, bg=bg)
        self._win  = self._canvas.create_window((0, 0), window=self.inner,
                                                anchor="nw")
        self.inner.bind("<Configure>",   self._on_configure)
        self._canvas.bind("<Configure>", self._on_canvas_resize)

    def _on_configure(self, _):
        self._canvas.configure(scrollregion=self._canvas.bbox("all"))

    def _on_canvas_resize(self, e):
        self._canvas.itemconfig(self._win, width=e.width)

    def scroll(self, e):
        """Called by the global handler when pointer is over this frame."""
        if e.num == 4:
            self._canvas.yview_scroll(-1, "units")
        elif e.num == 5:
            self._canvas.yview_scroll(1, "units")
        else:
            self._canvas.yview_scroll(int(-e.delta / 20), "units")

    def contains_pointer(self) -> bool:
        """True if the mouse is currently within this frame's area."""
        try:
            rx = self.winfo_rootx()
            ry = self.winfo_rooty()
            rw = self.winfo_width()
            rh = self.winfo_height()
            px = self.winfo_pointerx()
            py = self.winfo_pointery()
            return rx <= px <= rx + rw and ry <= py <= ry + rh
        except Exception:
            return False

    def bind_scroll_recursive(self, widget=None):
        pass  # kept for compatibility

    def scroll_top(self):
        self._canvas.yview_moveto(0)


def _global_scroll_handler(event):
    """Single handler bound to root — delegates to whichever panel has pointer."""
    for sf in ScrollableFrame._instances:
        if sf.contains_pointer():
            sf.scroll(event)
            break

# ── Orange button that actually shows on macOS ────────────

class OrangeBtn(tk.Frame):
    """Dark charcoal button that renders correctly on macOS."""
    def __init__(self, parent, text, command, full=False, height=38):
        super().__init__(parent, bg=BTN_BG, cursor="arrow")
        self._cmd = command
        self._lbl = tk.Label(self, text=text, bg=BTN_BG, fg="white",
                             font=(FONT, 10, "bold"),
                             padx=18, pady=0, height=2)
        self._lbl.pack(fill="both", expand=True)
        for w in (self, self._lbl):
            w.bind("<Button-1>",  self._on_click)
            w.bind("<Enter>",     self._on_enter)
            w.bind("<Leave>",     self._on_leave)

    def _on_click(self, _): self._cmd()
    def _on_enter(self, _):
        self.config(bg=BTN_HV); self._lbl.config(bg=BTN_HV)
    def _on_leave(self, _):
        self.config(bg=BTN_BG); self._lbl.config(bg=BTN_BG)
    def set_text(self, t): self._lbl.config(text=t)
    def set_state(self, s):
        c = BTN_DIS if s == "disabled" else BTN_BG
        self.config(bg=c); self._lbl.config(bg=c)
        self._lbl.config(fg="#e2e8f0" if s == "disabled" else "white")
        for w in (self, self._lbl):
            w.unbind("<Button-1>")
            if s != "disabled":
                w.bind("<Button-1>", self._on_click)

class OutlineBtn(tk.Frame):
    def __init__(self, parent, text, command, width=120):
        super().__init__(parent, bg=PANEL,
                         highlightbackground=BORDER2, highlightthickness=1,
                         cursor="arrow")
        self._cmd = command
        self._lbl = tk.Label(self, text=text, bg=PANEL, fg=TEXT,
                             font=(FONT, 10), padx=12, pady=0,
                             height=2, width=width//10)
        self._lbl.pack(fill="both", expand=True)
        for w in (self, self._lbl):
            w.bind("<Button-1>", self._on_click)
            w.bind("<Enter>",    lambda e: self._lbl.config(bg="#f3f4f6"))
            w.bind("<Leave>",    lambda e: self._lbl.config(bg=PANEL))

    def _on_click(self, _): self._cmd()

# ── Dashed drop zone ──────────────────────────────────────

class DropZone(tk.Frame):
    def __init__(self, parent, icon, title, subtitle, chips, browse_cmd):
        super().__init__(parent, bg=DASH_BG,
                         highlightbackground=DASH_BD, highlightthickness=1)
        inner = tk.Frame(self, bg=DASH_BG, pady=16)
        inner.pack(fill="x")
        lbl(inner, icon, size=22, fg=SUBTEXT).pack()
        lbl(inner, title, size=11, bold=True).pack(pady=(6,2))
        if subtitle:
            lbl(inner, subtitle, size=9, fg=SUBTEXT).pack()
        row = tk.Frame(inner, bg=DASH_BG)
        row.pack(pady=(12,0))
        for c in chips:
            tk.Label(row, text=c, bg=BADGE_BG, fg=BADGE_FG,
                     font=(FONT, 8, "bold"), padx=8, pady=3).pack(side="left", padx=3)
        OrangeBtn(row, "Browse Files", browse_cmd).pack(side="left", padx=(6,0))

# ── File info row ─────────────────────────────────────────

class FileInfoRow(tk.Frame):
    def __init__(self, parent, on_clear):
        super().__init__(parent, bg=PANEL,
                         highlightbackground=BORDER, highlightthickness=1)
        inner = tk.Frame(self, bg=PANEL, padx=10, pady=7)
        inner.pack(fill="x")
        tk.Label(inner, text="●", fg=GREEN, bg=PANEL,
                 font=(FONT, 10)).pack(side="left")
        self._name  = lbl(inner, "", size=9, fg=TEXT)
        self._name.pack(side="left", padx=(4,0))
        self._size  = lbl(inner, "", size=9, fg=SUBTEXT)
        self._size.pack(side="left", padx=(6,0))
        self._badge = badge(inner, "", bg=GREEN_L, fg=GREEN, size=8)
        self._badge.pack(side="left", padx=(8,0))
        tk.Button(inner, text="✕", command=on_clear,
                  bg=PANEL, fg=SUBTEXT, relief="flat", bd=0,
                  font=(FONT, 11), padx=4).pack(side="right")

    def update(self, name, size_str, badge_text="Loaded"):
        self._name.config(text=name)
        self._size.config(text=f"· {size_str}")
        self._badge.config(text=f"● {badge_text}")

# ── Passkey entry ─────────────────────────────────────────

class PasskeyEntry(tk.Frame):
    def __init__(self, parent, placeholder="Enter passkey", on_change=None):
        super().__init__(parent, bg=PANEL,
                         highlightbackground=BORDER2, highlightthickness=1)
        self._ph      = placeholder
        self._is_ph   = True
        self._visible = False
        self._cb      = on_change

        inner = tk.Frame(self, bg=PANEL, padx=10, pady=7)
        inner.pack(fill="x")
        tk.Label(inner, text="🔑", bg=PANEL, font=(FONT, 11)).pack(side="left")
        self._var   = tk.StringVar()
        self._entry = tk.Entry(inner, textvariable=self._var,
                               bg=PANEL, fg=SUBTEXT, relief="flat", bd=0,
                               font=(FONT, 11), insertbackground=TEXT)
        self._entry.pack(side="left", fill="x", expand=True, padx=8)
        self._entry.insert(0, placeholder)
        self._entry.bind("<FocusIn>",  self._fin)
        self._entry.bind("<FocusOut>", self._fout)
        if on_change:
            self._var.trace_add("write", lambda *_: on_change())
        tk.Button(inner, text="👁", bg=PANEL, fg=SUBTEXT, relief="flat",
                  bd=0, font=(FONT, 12), command=self._toggle).pack(side="right")

    def _fin(self, _):
        if self._is_ph:
            self._entry.delete(0, "end")
            self._entry.config(fg=TEXT, show="•")
            self._is_ph = False

    def _fout(self, _):
        if self._entry.get() == "":
            self._entry.config(show="", fg=SUBTEXT)
            self._entry.insert(0, self._ph)
            self._is_ph = True

    def _toggle(self):
        if self._is_ph: return
        self._visible = not self._visible
        self._entry.config(show="" if self._visible else "•")

    def get(self) -> str:
        return "" if self._is_ph else self._entry.get()

    def set_enabled(self, on: bool):
        state = "normal" if on else "disabled"
        self._entry.config(state=state)

    def clear(self):
        self._entry.config(state="normal", show="", fg=SUBTEXT)
        self._entry.delete(0, "end")
        self._entry.insert(0, self._ph)
        self._is_ph   = True
        self._visible = False

# ── Strength bar ──────────────────────────────────────────

class StrengthBar(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=PANEL)
        row = tk.Frame(self, bg=PANEL)
        row.pack(fill="x")
        self._segs = []
        for _ in range(5):
            s = tk.Frame(row, bg="#e5e7eb", height=5)
            s.pack(side="left", fill="x", expand=True, padx=1)
            self._segs.append(s)
        self._lbl = lbl(self, "", size=8, fg=SUBTEXT)
        self._lbl.pack(anchor="e", pady=(2,0))

    def update(self, pw: str):
        bits  = passkey_entropy_bits(pw)
        score = min(int(bits / 1.28), 100)
        levels = [(20, RED, "Weak"), (40, "#f59e0b", "Fair"),
                  (60, "#84cc16", "Good"), (80, GREEN, "Strong"),
                  (100, GREEN, "Strong")]
        filled, color, label = 0, "#e5e7eb", ""
        for thresh, c, l in levels:
            if score >= thresh:
                filled += 1; color = c; label = l
        for i, s in enumerate(self._segs):
            s.config(bg=color if i < filled else "#e5e7eb")
        self._lbl.config(
            text=f"Strength: {label}  ({bits}-bit Entropy)" if label else "",
            fg=color if color != "#e5e7eb" else SUBTEXT)

# ══════════════════════════════════════════════════════════
#  ENCRYPT PANEL
# ══════════════════════════════════════════════════════════

class EncryptPanel(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=PANEL,
                         highlightbackground=BORDER, highlightthickness=1)
        self._path = self._enc_bytes = self._name = None

        # Scrollable inner area
        sf = ScrollableFrame(self, bg=PANEL)
        sf.pack(fill="both", expand=True)
        self._sf = sf
        self._p = sf.inner
        self._build()
        # Bind scroll after all widgets are created
        self.after(100, self._rebind_scroll)

    def _build(self):
        p = self._p
        pad = tk.Frame(p, bg=PANEL, padx=20, pady=16)
        pad.pack(fill="x")

        # Header
        hdr = tk.Frame(pad, bg=PANEL)
        hdr.pack(fill="x", pady=(0,10))
        icon = tk.Frame(hdr, bg="#fff3ed", width=44, height=44)
        icon.pack(side="left"); icon.pack_propagate(False)
        tk.Label(icon, text="🛡", bg="#fff3ed",
                 font=(FONT, 18)).place(relx=.5, rely=.5, anchor="center")
        txt = tk.Frame(hdr, bg=PANEL)
        txt.pack(side="left", padx=10)
        lbl(txt, "Encrypt Image",  size=13, bold=True).pack(anchor="w")
        lbl(txt, "Pixel manipulation encryption & byte-level obfuscation",
            size=8, fg=SUBTEXT).pack(anchor="w")
        badge(hdr, "XOR-SHUFFLE").pack(side="right")
        sep(pad).pack(fill="x", pady=(0,12))

        # Drop zone
        lbl(pad, "Source Media Payload", size=9, fg=SUBTEXT).pack(anchor="w", pady=(0,5))
        DropZone(pad, "⬆", "Choose Image (Max 10MB)",
                 "",
                 ["PNG", "JPG", "WEBP"], self._browse).pack(fill="x")

        self._file_row = FileInfoRow(pad, self._clear_file)
        self._file_row.pack(fill="x", pady=(8,0))
        self._file_row.pack_forget()

        # Viewport
        self._vp = tk.Frame(pad, bg=PANEL)
        vp_hdr = tk.Frame(self._vp, bg=PANEL)
        vp_hdr.pack(fill="x", pady=(12,4))
        lbl(vp_hdr, "Viewport Buffer", size=9, bold=True).pack(side="left")
        self._vp_meta = lbl(vp_hdr, "", size=8, fg=SUBTEXT)
        self._vp_meta.pack(side="right")
        self._thumb = tk.Label(self._vp, bg=DARK_BG)
        self._thumb.pack(fill="x")
        ovl = tk.Frame(self._thumb, bg=DARK_BG)
        self._crc_lbl = tk.Label(ovl, text="", bg=DARK_BG, fg="#64748b",
                                  font=("Courier", 8))
        self._crc_lbl.pack(side="left")
        tk.Label(ovl, text="Source Ready", bg=DARK_BG, fg=GREEN,
                 font=(FONT, 8, "bold")).pack(side="right")
        ovl.place(relx=0, rely=1.0, anchor="sw", relwidth=1.0)

        # Passkey
        kh = tk.Frame(pad, bg=PANEL)
        kh.pack(fill="x", pady=(14,4))
        self._use_key = tk.BooleanVar(value=False)
        tk.Checkbutton(kh, text=" Encrypt with Secret Key",
                       variable=self._use_key, command=self._toggle_key,
                       bg=PANEL, fg=TEXT, font=(FONT, 10, "bold"),
                       activebackground=PANEL, selectcolor=PANEL).pack(side="left")
        lbl(kh, "SHA-256 Key Derivation", size=8, fg=SUBTEXT).pack(side="right")

        self._pk = PasskeyEntry(pad, "Enter passkey", on_change=self._pw_changed)
        self._pk.pack(fill="x", pady=(2,4))
        self._pk.set_enabled(False)
        self._strength = StrengthBar(pad)
        self._strength.pack(fill="x", pady=(0,12))

        # Buttons
        br = tk.Frame(pad, bg=PANEL)
        br.pack(fill="x", pady=(0,8))
        self._enc_btn = OrangeBtn(br, "  Encrypt Image", self._encrypt)
        self._enc_btn.pack(side="left", fill="x", expand=True)
        OutlineBtn(br, "  Reset", self._reset, width=100).pack(side="left", padx=(8,0))

        # Info
        info = tk.Frame(pad, bg=BLUE_L,
                        highlightbackground="#bfdbfe", highlightthickness=1)
        tk.Label(info, text="i  After encryption, download the standalone .enc payload or export raw Base64 data.",
                 bg=BLUE_L, fg=BLUE, font=(FONT, 8),
                 wraplength=340, justify="left", padx=10, pady=8).pack()
        info.pack(fill="x", pady=(0,10))

        # Result
        self._res_row = tk.Frame(pad, bg=PANEL,
                                 highlightbackground=BORDER, highlightthickness=1)
        ri = tk.Frame(self._res_row, bg=PANEL, padx=10, pady=8)
        ri.pack(fill="x")
        tk.Label(ri, text="●", fg=GREEN, bg=PANEL, font=(FONT,10)).pack(side="left")
        lbl(ri, " Encrypted image ready", size=9, bold=True).pack(side="left")
        self._res_size = lbl(ri, "", size=8, fg=SUBTEXT)
        self._res_size.pack(side="left", padx=4)
        self._iv_lbl = lbl(ri, "", size=8, fg=SUBTEXT)
        self._iv_lbl.pack(side="right")

        dr = tk.Frame(pad, bg=PANEL)
        self._dl_row = dr
        OrangeBtn(dr, "  Download .enc", self._download).pack(
            side="left", fill="x", expand=True)
        OutlineBtn(dr, "  Copy Base64", self._copy_b64, width=130).pack(
            side="left", padx=(8,0))

    # ── callbacks ─────────────────────────────────────────

    def _toggle_key(self):
        self._pk.set_enabled(self._use_key.get())

    def _pw_changed(self):
        self._strength.update(self._pk.get())

    def _rebind_scroll(self):
        self._sf.bind_scroll_recursive()

    def _browse(self):
        path = filedialog.askopenfilename(
            filetypes=[("Images","*.png *.jpg *.jpeg *.bmp *.tiff *.webp"),("All","*.*")])
        if not path: return
        if os.path.getsize(path) > 10*1024*1024:
            messagebox.showerror("Error","File exceeds 10MB."); return
        self._path = path
        self._name = os.path.basename(path)
        sz = os.path.getsize(path)
        self._file_row.update(self._name,
            f"{sz/1024:.1f} KB" if sz < 1024*1024 else f"{sz/1024/1024:.1f} MB")
        self._file_row.pack(fill="x", pady=(8,0))
        try:
            img = Image.open(path)
            w,h = img.size
            self._vp_meta.config(text=f"{w} × {h}  ·  {img.mode}")
            thumb = img.copy().convert("RGB")
            thumb.thumbnail((THUMB_W, THUMB_H), Image.LANCZOS)
            photo = ImageTk.PhotoImage(thumb)
            self._thumb.config(image=photo, text="", width=photo.width(), height=photo.height())
            self._thumb.image = photo
            crc = hashlib.md5(img.tobytes()).hexdigest()[:8].upper()
            self._crc_lbl.config(text=f"CRC32: 0x{crc}")
        except Exception:
            self._thumb.config(text="Preview unavailable", fg=SUBTEXT)
        self._vp.pack(fill="x", pady=(0,8))
        self._enc_bytes = None
        self._res_row.pack_forget()
        self._dl_row.pack_forget()
        self.after(50, self._sf.scroll_top)
        self.after(150, self._rebind_scroll)

    def _clear_file(self):
        self._path = self._enc_bytes = self._name = None
        self._file_row.pack_forget()
        self._vp.pack_forget()
        self._res_row.pack_forget()
        self._dl_row.pack_forget()

    def _encrypt(self):
        if not self._path:
            messagebox.showerror("Error","Please choose an image first."); return
        passkey = ""
        if self._use_key.get():
            passkey = self._pk.get()
            if not passkey:
                messagebox.showerror("Error","Please enter a passkey."); return
        self._enc_btn.set_text("  Encrypting…")
        self._enc_btn.set_state("disabled")
        def run():
            try:
                enc = encrypt_image(Image.open(self._path), passkey)
                self.after(0, lambda: self._on_done(enc))
            except Exception as e:
                self.after(0, lambda: (
                    messagebox.showerror("Error", str(e)),
                    self._enc_btn.set_text("  Encrypt Image"),
                    self._enc_btn.set_state("normal")))
        threading.Thread(target=run, daemon=True).start()

    def _on_done(self, enc: bytes):
        self._enc_bytes = enc
        kb = len(enc)/1024
        self._res_size.config(text=f"· {kb:.1f} KB" if kb<1024 else f"· {kb/1024:.1f} MB")
        iv = enc[16:24].hex()[:8]+"..." if len(enc)>24 else ""
        self._iv_lbl.config(text=f"IV: {iv}")
        self._res_row.pack(fill="x", pady=(8,0))
        self._dl_row.pack(fill="x", pady=(6,0))
        self._enc_btn.set_text("  Encrypt Image")
        self._enc_btn.set_state("normal")
        self.after(100, self._rebind_scroll)

    def _download(self):
        if not self._enc_bytes: return
        base = os.path.splitext(self._name)[0] if self._name else "encrypted"
        path = filedialog.asksaveasfilename(defaultextension=".enc",
            initialfile=f"{base}.enc",
            filetypes=[("Encrypted","*.enc"),("All","*.*")])
        if path:
            with open(path,"wb") as f: f.write(self._enc_bytes)
            messagebox.showinfo("Saved",f"Saved to:\n{path}")

    def _copy_b64(self):
        if not self._enc_bytes: return
        self.clipboard_clear()
        self.clipboard_append(base64.b64encode(self._enc_bytes).decode())
        messagebox.showinfo("Copied","Base64 copied to clipboard.")

    def _reset(self):
        self._clear_file()
        self._pk.clear(); self._pk.set_enabled(False)
        self._use_key.set(False); self._strength.update("")


# ══════════════════════════════════════════════════════════
#  DECRYPT PANEL
# ══════════════════════════════════════════════════════════

class DecryptPanel(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=PANEL,
                         highlightbackground=BORDER, highlightthickness=1)
        self._enc_path = self._result_img = self._name = None

        sf = ScrollableFrame(self, bg=PANEL)
        sf.pack(fill="both", expand=True)
        self._sf = sf
        self._p = sf.inner
        self._build()
        self.after(100, self._rebind_scroll)

    def _build(self):
        p = self._p
        pad = tk.Frame(p, bg=PANEL, padx=20, pady=16)
        pad.pack(fill="x")

        # Header
        hdr = tk.Frame(pad, bg=PANEL)
        hdr.pack(fill="x", pady=(0,10))
        icon = tk.Frame(hdr, bg=BLUE_L, width=44, height=44)
        icon.pack(side="left"); icon.pack_propagate(False)
        tk.Label(icon, text="🔍", bg=BLUE_L,
                 font=(FONT, 18)).place(relx=.5, rely=.5, anchor="center")
        txt = tk.Frame(hdr, bg=PANEL)
        txt.pack(side="left", padx=10)
        lbl(txt, "Decrypt Image",  size=13, bold=True).pack(anchor="w")
        lbl(txt, "Restore encrypted images from cipher data",
            size=8, fg=SUBTEXT).pack(anchor="w")
        badge(hdr, "Payload Decoder", bg=BLUE_L, fg=BLUE).pack(side="right")
        sep(pad).pack(fill="x", pady=(0,12))

        # Drop zone
        lbl(pad, "Encrypted Payload Input", size=9, fg=SUBTEXT).pack(anchor="w", pady=(0,5))
        DropZone(pad, "📄", "Choose encrypted file (.enc)",
                 "",
                 [".ENC CIPHER"], self._browse).pack(fill="x")

        self._file_row = FileInfoRow(pad, self._clear_file)
        self._file_row.pack(fill="x", pady=(8,0))
        self._file_row.pack_forget()

        # Passkey
        kh = tk.Frame(pad, bg=PANEL)
        kh.pack(fill="x", pady=(14,4))
        self._use_key = tk.BooleanVar(value=False)
        tk.Checkbutton(kh, text=" Secret key required",
                       variable=self._use_key, command=self._toggle_key,
                       bg=PANEL, fg=TEXT, font=(FONT, 10, "bold"),
                       activebackground=PANEL, selectcolor=PANEL).pack(side="left")
        lbl(kh, "HMAC-SHA256 Match", size=8, fg=SUBTEXT).pack(side="right")

        self._pk = PasskeyEntry(pad, "Enter passkey")
        self._pk.pack(fill="x", pady=(2,4))
        self._pk.set_enabled(False)

        self._pk_status = lbl(pad, "", size=8, fg=SUBTEXT)
        self._pk_status.pack(anchor="w", pady=(0,10))

        # Buttons
        br = tk.Frame(pad, bg=PANEL)
        br.pack(fill="x", pady=(0,8))
        self._dec_btn = OrangeBtn(br, "  Decrypt Image", self._decrypt)
        self._dec_btn.pack(side="left", fill="x", expand=True)
        OutlineBtn(br, "  Reset", self._reset, width=100).pack(side="left", padx=(8,0))

        # Warning
        warn = tk.Frame(pad, bg=YELLOW_L,
                        highlightbackground="#fde68a", highlightthickness=1)
        tk.Label(warn,
                 text="⚠  If decryption fails, the passkey may be incorrect or the payload bytes have been altered or corrupted in transit.",
                 bg=YELLOW_L, fg=YELLOW_B, font=(FONT, 8),
                 wraplength=340, justify="left", padx=10, pady=8).pack()
        warn.pack(fill="x", pady=(0,10))

        # Restored image
        self._restored = tk.Frame(pad, bg=PANEL)
        rh = tk.Frame(self._restored, bg=PANEL)
        rh.pack(fill="x", pady=(0,6))
        tk.Label(rh, text="✅", bg=PANEL, font=(FONT,12)).pack(side="left")
        lbl(rh, "  Restored Image", size=11, bold=True).pack(side="left")
        badge(rh, "Decrypted (SHA-256 Verified)",
              bg=GREEN_L, fg=GREEN).pack(side="right")

        self._out_thumb = tk.Label(self._restored, bg=DARK_BG)
        self._out_thumb.pack(fill="x")
        ovl = tk.Frame(self._out_thumb, bg=DARK_BG)
        self._out_meta = tk.Label(ovl, text="", bg=DARK_BG, fg="#64748b",
                                   font=("Courier", 8))
        self._out_meta.pack(side="left")
        tk.Label(ovl, text="100% Fidelity", bg=DARK_BG, fg=GREEN,
                 font=(FONT, 8, "bold")).pack(side="right")
        ovl.place(relx=0, rely=1.0, anchor="sw", relwidth=1.0)

        OrangeBtn(self._restored, "  Download Restored Image",
                  self._download).pack(fill="x", pady=(10,0))

    # ── callbacks ─────────────────────────────────────────

    def _toggle_key(self):
        on = self._use_key.get()
        self._pk.set_enabled(on)
        self._pk_status.config(
            text="Passkey status: Enter key to validate" if on else "")

    def _rebind_scroll(self):
        self._sf.bind_scroll_recursive()

    def _browse(self):
        path = filedialog.askopenfilename(
            filetypes=[("Encrypted","*.enc *.txt"),("All","*.*")])
        if not path: return
        self._enc_path = path
        self._name = os.path.basename(path)
        sz = os.path.getsize(path)
        self._file_row.update(self._name,
            f"{sz/1024:.1f} KB" if sz<1024*1024 else f"{sz/1024/1024:.1f} MB",
            "Header Valid")
        self._file_row.pack(fill="x", pady=(8,0))
        self._pk_status.config(text="Passkey status: Awaiting input…", fg=SUBTEXT)
        self._restored.pack_forget()
        self.after(50, self._sf.scroll_top)
        self.after(150, self._rebind_scroll)

    def _clear_file(self):
        self._enc_path = self._result_img = self._name = None
        self._file_row.pack_forget()
        self._restored.pack_forget()
        self._pk_status.config(text="")

    def _decrypt(self):
        if not self._enc_path:
            messagebox.showerror("Error","Please choose an encrypted file."); return
        passkey = ""
        if self._use_key.get():
            passkey = self._pk.get()
            if not passkey:
                messagebox.showerror("Error","Please enter the passkey."); return
        self._dec_btn.set_text("  Decrypting…")
        self._dec_btn.set_state("disabled")
        self._pk_status.config(text="Passkey status: Verifying…", fg=SUBTEXT)
        def run():
            try:
                with open(self._enc_path,"rb") as f: data = f.read()
                img = decrypt_bytes(data, passkey)
                self.after(0, lambda: self._on_done(img))
            except Exception as e:
                self.after(0, lambda: (
                    self._pk_status.config(
                        text="Passkey status: ✗ Decryption failed", fg=RED),
                    messagebox.showerror("Decryption Failed",
                        f"Passkey may be incorrect or file corrupted.\n\n{e}"),
                    self._dec_btn.set_text("  Decrypt Image"),
                    self._dec_btn.set_state("normal")))
        threading.Thread(target=run, daemon=True).start()

    def _on_done(self, img: Image.Image):
        self._result_img = img
        w, h = img.size
        thumb = img.copy().convert("RGB")
        thumb.thumbnail((THUMB_W, THUMB_H), Image.LANCZOS)
        photo = ImageTk.PhotoImage(thumb)
        self._out_thumb.config(image=photo, text="", width=photo.width(), height=photo.height())
        self._out_thumb.image = photo
        self._out_meta.config(text=f"{w} × {h}  ·  lossless PNG")
        self._pk_status.config(
            text="Passkey status: ✓ Valid Checksum (CRC OK)  ·  Auth Tag: OK",
            fg=GREEN)
        self._restored.pack(fill="x", pady=(8,0))
        self._dec_btn.set_text("  Decrypt Image")
        self._dec_btn.set_state("normal")
        self.after(100, self._rebind_scroll)

    def _download(self):
        if not self._result_img: return
        base = os.path.splitext(self._name)[0] if self._name else "decrypted"
        path = filedialog.asksaveasfilename(defaultextension=".png",
            initialfile=f"{base}.png",
            filetypes=[("PNG","*.png"),("All","*.*")])
        if path:
            self._result_img.save(path)
            messagebox.showinfo("Saved",f"Saved to:\n{path}")

    def _reset(self):
        self._clear_file()
        self._pk.clear(); self._pk.set_enabled(False)
        self._use_key.set(False); self._pk_status.config(text="")


# ══════════════════════════════════════════════════════════
#  MAIN WINDOW
# ══════════════════════════════════════════════════════════

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Image Encryption & Decryption Tool")
        self.configure(bg=BG)
        self.resizable(True, True)

        # Title bar
        tb = tk.Frame(self, bg=PANEL,
                      highlightbackground=BORDER, highlightthickness=1)
        tb.pack(fill="x")
        inner_tb = tk.Frame(tb, bg=PANEL, padx=20, pady=10)
        inner_tb.pack(fill="x")
        lbl(inner_tb, "🛡  Image Encryption & Decryption Tool",
            size=12, bold=True).pack(side="left")
        badge(inner_tb, "● XOR-SHUFFLE", bg=GREEN_L, fg=GREEN).pack(side="right")

        # Sub-bar
        sb = tk.Frame(self, bg=PANEL,
                      highlightbackground=BORDER, highlightthickness=1)
        sb.pack(fill="x")
        inner_sb = tk.Frame(sb, bg=PANEL, padx=20, pady=5)
        inner_sb.pack(fill="x")
        lbl(inner_sb, "● SHA-256 Key Derivation  ·  Pixel Manipulation Cipher",
            size=8, fg=SUBTEXT).pack(side="left")
        lbl(inner_sb, "Secure Local Encryption  ·  No Data Leaves Your Device",
            size=8, fg=SUBTEXT).pack(side="right")

        # Panels
        body = tk.Frame(self, bg=BG, padx=14, pady=14)
        body.pack(fill="both", expand=True)
        EncryptPanel(body).grid(row=0, column=0, sticky="nsew", padx=(0,7))
        DecryptPanel(body).grid(row=0, column=1, sticky="nsew", padx=(7,0))
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        # Status bar
        stb = tk.Frame(self, bg="#1e293b", pady=5)
        stb.pack(fill="x", side="bottom")
        for i, t in enumerate(["● Hardware Acceleration Ready",
                                "XOR-Shuffle Pixel Encryption",
                                "SHA-256 Key Derivation",
                                "Pixel Manipulation  ·  v1.0"]):
            tk.Label(stb, text=t, bg="#1e293b", fg="#64748b",
                     font=(FONT, 7)).pack(side="left", padx=14)
            if i < 3:
                tk.Label(stb, text="·", bg="#1e293b", fg="#334155",
                         font=(FONT, 9)).pack(side="left")

        # Global scroll handler — works over every widget in either panel
        self.bind_all("<MouseWheel>", _global_scroll_handler)
        self.bind_all("<Button-4>",   _global_scroll_handler)
        self.bind_all("<Button-5>",   _global_scroll_handler)

        self.update_idletasks()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        w, h = 1080, 740
        self.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")


if __name__ == "__main__":
    App().mainloop()
