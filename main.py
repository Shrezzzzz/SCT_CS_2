"""
Image Encryption Tool
=====================
A single-file tool that encrypts and decrypts images using pixel manipulation.

Encryption modes:
  - XOR      : XORs every pixel channel with (key % 256). Self-reversing.
  - Swap     : Shuffles pixel positions using a key-seeded RNG.
  - Combined : XOR then Swap — strongest scrambling (default).

Run with:
  python main.py
"""

import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import os
import random

import numpy as np
from PIL import Image, ImageTk


# ══════════════════════════════════════════════════════════
#  CORE ENCRYPTION / DECRYPTION LOGIC
# ══════════════════════════════════════════════════════════

def xor_encrypt(pixels: np.ndarray, key: int) -> np.ndarray:
    """XOR every pixel channel with (key % 256). Running again decrypts."""
    return (pixels ^ (key % 256)).astype(np.uint8)

xor_decrypt = xor_encrypt  # XOR is self-reversing


def _shuffle_indices(total: int, key: int) -> list[int]:
    indices = list(range(total))
    random.seed(key)
    random.shuffle(indices)
    return indices


def swap_encrypt(pixels: np.ndarray, key: int) -> np.ndarray:
    """Shuffle pixel positions using a seeded RNG."""
    flat = pixels.reshape(-1, pixels.shape[2])
    shuffled = flat[_shuffle_indices(len(flat), key)]
    return shuffled.reshape(pixels.shape).astype(np.uint8)


def swap_decrypt(pixels: np.ndarray, key: int) -> np.ndarray:
    """Reverse the shuffle to restore original pixel positions."""
    flat = pixels.reshape(-1, pixels.shape[2])
    restored = np.empty_like(flat)
    for orig, shuf in enumerate(_shuffle_indices(len(flat), key)):
        restored[orig] = flat[shuf]
    return restored.reshape(pixels.shape).astype(np.uint8)


def combined_encrypt(pixels: np.ndarray, key: int) -> np.ndarray:
    return swap_encrypt(xor_encrypt(pixels, key), key)


def combined_decrypt(pixels: np.ndarray, key: int) -> np.ndarray:
    return xor_decrypt(swap_decrypt(pixels, key), key)


MODES = {
    "xor":      (xor_encrypt,      xor_decrypt),
    "swap":     (swap_encrypt,     swap_decrypt),
    "combined": (combined_encrypt, combined_decrypt),
}


def process_image(input_path: str, output_path: str,
                  key: int, mode: str = "combined",
                  operation: str = "encrypt") -> None:
    """Load → transform pixels → save."""
    enc_fn, dec_fn = MODES[mode]
    fn = enc_fn if operation == "encrypt" else dec_fn

    img = Image.open(input_path)
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGB")

    result = fn(np.array(img, dtype=np.uint8), key)
    Image.fromarray(result, img.mode).save(output_path)


# ══════════════════════════════════════════════════════════
#  GUI
# ══════════════════════════════════════════════════════════

BG       = "#1e1e2e"
CARD     = "#2a2a3e"
ACCENT   = "#7c6af7"
ACCENT_H = "#9d8fff"
TEXT     = "#cdd6f4"
SUBTEXT  = "#a6adc8"
BORDER   = "#45475a"
THUMB_W  = 220
THUMB_H  = 160


def styled_btn(parent, text, command, bg=ACCENT, fg="white", width=18):
    b = tk.Button(
        parent, text=text, command=command,
        bg=bg, fg=fg, activebackground=ACCENT_H, activeforeground="white",
        relief="flat", bd=0, padx=12, pady=8,
        font=("Helvetica", 11, "bold"), cursor="hand2", width=width,
    )
    b.bind("<Enter>", lambda e: b.config(bg=ACCENT_H))
    b.bind("<Leave>", lambda e: b.config(bg=bg))
    return b


class ImageEncryptorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Image Encryption Tool")
        self.configure(bg=BG)
        self.resizable(False, False)

        self.input_path  = tk.StringVar()
        self.output_path = tk.StringVar()
        self.key_var     = tk.StringVar(value="42")
        self.mode_var    = tk.StringVar(value="combined")
        self.op_var      = tk.StringVar(value="encrypt")

        self._build_ui()
        self._center_window(780, 620)

    # ── Layout ────────────────────────────────────────────
    def _build_ui(self):
        # Title
        tf = tk.Frame(self, bg=ACCENT, pady=14)
        tf.pack(fill="x")
        tk.Label(tf, text="🔐  Image Encryption Tool",
                 bg=ACCENT, fg="white",
                 font=("Helvetica", 16, "bold")).pack()

        # Body
        body = tk.Frame(self, bg=BG, padx=24, pady=18)
        body.pack(fill="both", expand=True)

        left = tk.Frame(body, bg=BG)
        left.grid(row=0, column=0, sticky="n", padx=(0, 20))
        right = tk.Frame(body, bg=BG)
        right.grid(row=0, column=1, sticky="n")

        self._build_controls(left)
        self._build_previews(right)

        # Status bar
        self.status_var = tk.StringVar(value="Ready — select an image to get started.")
        tk.Label(self, textvariable=self.status_var,
                 bg=CARD, fg=SUBTEXT, font=("Helvetica", 10),
                 anchor="w", padx=14, pady=6).pack(fill="x", side="bottom")

    def _build_controls(self, parent):
        def section(text):
            tk.Label(parent, text=text, bg=BG, fg=SUBTEXT,
                     font=("Helvetica", 9, "bold")).pack(anchor="w", pady=(14, 2))

        def card():
            f = tk.Frame(parent, bg=CARD, padx=14, pady=12,
                         highlightbackground=BORDER, highlightthickness=1)
            f.pack(fill="x", pady=(0, 4))
            return f

        # Input
        section("INPUT IMAGE")
        f = card()
        tk.Entry(f, textvariable=self.input_path, width=32,
                 bg="#313244", fg=TEXT, insertbackground=TEXT,
                 relief="flat", font=("Helvetica", 10)).pack(side="left")
        styled_btn(f, "Browse", self._browse_input, width=8).pack(side="left", padx=(8, 0))

        # Output
        section("OUTPUT IMAGE")
        f = card()
        tk.Entry(f, textvariable=self.output_path, width=32,
                 bg="#313244", fg=TEXT, insertbackground=TEXT,
                 relief="flat", font=("Helvetica", 10)).pack(side="left")
        styled_btn(f, "Browse", self._browse_output, width=8).pack(side="left", padx=(8, 0))

        # Key
        section("ENCRYPTION KEY  (any integer)")
        f = card()
        tk.Entry(f, textvariable=self.key_var, width=20,
                 bg="#313244", fg=TEXT, insertbackground=TEXT,
                 relief="flat", font=("Helvetica", 13)).pack(anchor="w")

        # Mode
        section("MODE")
        f = card()
        for val, label, desc in [
            ("xor",      "XOR",      "Fast, self-reversing"),
            ("swap",     "Swap",     "Shuffles pixel positions"),
            ("combined", "Combined", "XOR + Swap  (strongest)"),
        ]:
            row = tk.Frame(f, bg=CARD)
            row.pack(anchor="w", pady=2)
            tk.Radiobutton(row, text=f"  {label}", variable=self.mode_var, value=val,
                           bg=CARD, fg=TEXT, selectcolor=ACCENT,
                           activebackground=CARD, activeforeground=TEXT,
                           font=("Helvetica", 11)).pack(side="left")
            tk.Label(row, text=f"— {desc}", bg=CARD, fg=SUBTEXT,
                     font=("Helvetica", 9)).pack(side="left")

        # Operation
        section("OPERATION")
        f = card()
        for val, label in [("encrypt", "🔒  Encrypt"), ("decrypt", "🔓  Decrypt")]:
            tk.Radiobutton(f, text=label, variable=self.op_var, value=val,
                           bg=CARD, fg=TEXT, selectcolor=ACCENT,
                           activebackground=CARD, activeforeground=TEXT,
                           font=("Helvetica", 11)).pack(side="left", padx=(0, 16))

        # Run button
        tk.Frame(parent, bg=BG, height=10).pack()
        styled_btn(parent, "▶   Run", self._run, width=36).pack(fill="x")

    def _build_previews(self, parent):
        for label, attr in [("INPUT PREVIEW", "in_canvas"),
                             ("OUTPUT PREVIEW", "out_canvas")]:
            tk.Label(parent, text=label, bg=BG, fg=SUBTEXT,
                     font=("Helvetica", 9, "bold")).pack(anchor="w", pady=(14, 4))
            canvas = tk.Label(parent, bg=CARD, width=THUMB_W, height=THUMB_H,
                              text="No image selected" if "INPUT" in label else "Output will appear here",
                              fg=SUBTEXT, font=("Helvetica", 10),
                              highlightbackground=BORDER, highlightthickness=1)
            canvas.pack()
            setattr(self, attr, canvas)

    # ── File dialogs ──────────────────────────────────────
    def _browse_input(self):
        path = filedialog.askopenfilename(
            title="Select input image",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp *.tiff *.webp"), ("All", "*.*")]
        )
        if path:
            self.input_path.set(path)
            base, _ = os.path.splitext(path)
            suffix = "_encrypted" if self.op_var.get() == "encrypt" else "_decrypted"
            self.output_path.set(f"{base}{suffix}.png")
            self._show_preview(path, self.in_canvas)
            self.status_var.set(f"Input: {os.path.basename(path)}")

    def _browse_output(self):
        path = filedialog.asksaveasfilename(
            title="Save output image as",
            defaultextension=".png",
            filetypes=[("PNG", "*.png"), ("All", "*.*")]
        )
        if path:
            self.output_path.set(path)

    # ── Preview ───────────────────────────────────────────
    def _show_preview(self, path: str, widget: tk.Label):
        try:
            img = Image.open(path).convert("RGB")
            img.thumbnail((THUMB_W, THUMB_H), Image.LANCZOS)
            photo = ImageTk.PhotoImage(img)
            widget.config(image=photo, text="")
            widget.image = photo
        except Exception:
            widget.config(image="", text="Preview unavailable")

    # ── Validation ────────────────────────────────────────
    def _validate(self):
        if not self.input_path.get():
            return False, "Please select an input image."
        if not os.path.isfile(self.input_path.get()):
            return False, f"Input file not found:\n{self.input_path.get()}"
        if not self.output_path.get():
            return False, "Please specify an output file path."
        if not self.key_var.get().lstrip("-").isdigit():
            return False, "Key must be an integer (e.g. 42, 1337)."
        return True, ""

    # ── Run ───────────────────────────────────────────────
    def _run(self):
        ok, msg = self._validate()
        if not ok:
            messagebox.showerror("Validation Error", msg)
            return
        self.status_var.set("Processing…")
        self.update_idletasks()
        threading.Thread(target=self._do_process, daemon=True).start()

    def _do_process(self):
        try:
            process_image(
                input_path=self.input_path.get(),
                output_path=self.output_path.get(),
                key=int(self.key_var.get()),
                mode=self.mode_var.get(),
                operation=self.op_var.get(),
            )
            self.after(0, self._on_success)
        except Exception as e:
            self.after(0, lambda: self._on_error(str(e)))

    def _on_success(self):
        op  = self.op_var.get().capitalize()
        out = self.output_path.get()
        self.status_var.set(f"✅  {op}ion complete → {os.path.basename(out)}")
        self._show_preview(out, self.out_canvas)
        messagebox.showinfo("Done", f"{op}ion complete!\n\nSaved to:\n{out}")

    def _on_error(self, msg):
        self.status_var.set(f"❌  Error: {msg}")
        messagebox.showerror("Error", msg)

    # ── Center window ─────────────────────────────────────
    def _center_window(self, w, h):
        self.update_idletasks()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")


# ══════════════════════════════════════════════════════════
if __name__ == "__main__":
    ImageEncryptorApp().mainloop()
