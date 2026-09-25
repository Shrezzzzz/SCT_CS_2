"""
Image Encryption Tool — Core Logic
Supports two modes:
  1. XOR  : applies XOR with a numeric key to every pixel channel (self-reversing)
  2. Swap : shuffles pixel positions using a key-seeded RNG (reversible)
"""

import numpy as np
from PIL import Image
import random


# ─────────────────────────────────────────────
# XOR mode
# ─────────────────────────────────────────────

def xor_encrypt(pixels: np.ndarray, key: int) -> np.ndarray:
    """
    XOR every pixel channel value with (key % 256).
    Running the same function again decrypts the image.
    """
    key_byte = key % 256
    return (pixels ^ key_byte).astype(np.uint8)


# XOR decrypt is identical to encrypt (XOR is self-reversing)
xor_decrypt = xor_encrypt


# ─────────────────────────────────────────────
# Pixel-swap (shuffle) mode
# ─────────────────────────────────────────────

def _generate_shuffle_indices(total_pixels: int, key: int) -> list[int]:
    """Return a shuffled list of pixel indices seeded by key."""
    indices = list(range(total_pixels))
    random.seed(key)
    random.shuffle(indices)
    return indices


def swap_encrypt(pixels: np.ndarray, key: int) -> np.ndarray:
    """
    Shuffle pixel positions using a seeded RNG.
    Original shape is preserved; only positions change.
    """
    h, w = pixels.shape[:2]
    flat = pixels.reshape(-1, pixels.shape[2])          # (N, channels)
    indices = _generate_shuffle_indices(len(flat), key)
    shuffled = flat[indices]
    return shuffled.reshape(pixels.shape).astype(np.uint8)


def swap_decrypt(pixels: np.ndarray, key: int) -> np.ndarray:
    """
    Reverse the shuffle by placing each pixel back to its original position.
    """
    h, w = pixels.shape[:2]
    flat = pixels.reshape(-1, pixels.shape[2])          # (N, channels)
    indices = _generate_shuffle_indices(len(flat), key)

    restored = np.empty_like(flat)
    for original_pos, shuffled_pos in enumerate(indices):
        restored[original_pos] = flat[shuffled_pos]

    return restored.reshape(pixels.shape).astype(np.uint8)


# ─────────────────────────────────────────────
# Combined mode (XOR + Swap)
# ─────────────────────────────────────────────

def combined_encrypt(pixels: np.ndarray, key: int) -> np.ndarray:
    """Apply XOR first, then shuffle — maximum scrambling."""
    after_xor = xor_encrypt(pixels, key)
    return swap_encrypt(after_xor, key)


def combined_decrypt(pixels: np.ndarray, key: int) -> np.ndarray:
    """Reverse: unshuffle first, then XOR."""
    after_unshuffle = swap_decrypt(pixels, key)
    return xor_decrypt(after_unshuffle, key)


# ─────────────────────────────────────────────
# Image I/O helpers
# ─────────────────────────────────────────────

def load_image(path: str) -> tuple[np.ndarray, str]:
    """
    Load an image and return (pixel_array, mode).
    Converts to RGB or RGBA to ensure consistent channel count.
    """
    img = Image.open(path)
    mode = img.mode
    # Normalise to RGB or RGBA
    if mode not in ("RGB", "RGBA"):
        img = img.convert("RGB")
        mode = "RGB"
    return np.array(img, dtype=np.uint8), mode


def save_image(pixels: np.ndarray, mode: str, path: str) -> None:
    """Save a pixel array back to disk as an image."""
    img = Image.fromarray(pixels, mode)
    img.save(path)
    print(f"  Saved → {path}")


# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────

MODES = {
    "xor":      (xor_encrypt,      xor_decrypt),
    "swap":     (swap_encrypt,     swap_decrypt),
    "combined": (combined_encrypt, combined_decrypt),
}


def process_image(
    input_path: str,
    output_path: str,
    key: int,
    mode: str = "combined",
    operation: str = "encrypt",
) -> None:
    """
    High-level entry point used by the CLI.

    Args:
        input_path:  Path to the source image.
        output_path: Path where the result will be saved.
        key:         Integer key (any size; used mod 256 for XOR).
        mode:        One of 'xor', 'swap', 'combined'.
        operation:   'encrypt' or 'decrypt'.
    """
    if mode not in MODES:
        raise ValueError(f"Unknown mode '{mode}'. Choose from: {', '.join(MODES)}")

    encrypt_fn, decrypt_fn = MODES[mode]
    fn = encrypt_fn if operation == "encrypt" else decrypt_fn

    print(f"  Loading  : {input_path}")
    pixels, img_mode = load_image(input_path)

    print(f"  Mode     : {mode}  |  Operation: {operation}  |  Key: {key}")
    result = fn(pixels, key)

    save_image(result, img_mode, output_path)
