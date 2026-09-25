# Image Encryption Tool

A simple Python tool that encrypts and decrypts images using pixel manipulation — no external encryption libraries required.

## How It Works

Three encryption modes are available:

| Mode       | What it does                                              | Reversible |
|------------|-----------------------------------------------------------|------------|
| `xor`      | XORs every pixel channel with `key % 256`                | ✅ Self-reversing |
| `swap`     | Shuffles pixel positions using the key as an RNG seed     | ✅ With same key |
| `combined` | XOR first, then shuffle (default — strongest scrambling)  | ✅ With same key |

> **Important:** You must use the **same key and mode** to decrypt that you used to encrypt.

---

## Setup

```bash
pip install -r requirements.txt
```

---

## Usage

```bash
python main.py <encrypt|decrypt> <input_image> <output_image> --key <integer> [--mode <xor|swap|combined>]
```

### Encrypt an image

```bash
python main.py encrypt photo.png encrypted.png --key 42
```

### Decrypt it back

```bash
python main.py decrypt encrypted.png restored.png --key 42
```

### Use a specific mode

```bash
# XOR only
python main.py encrypt photo.png out_xor.png --key 42 --mode xor

# Pixel swap only
python main.py encrypt photo.png out_swap.png --key 42 --mode swap

# XOR + swap (default)
python main.py encrypt photo.png out_combined.png --key 42 --mode combined
```

---

## Project Structure

```
SCT_CS_2/
├── main.py          # CLI entry point
├── encryptor.py     # Core encryption/decryption logic
├── requirements.txt # Dependencies (pillow, numpy)
└── README.md
```

---

## Supported Image Formats

PNG, JPG/JPEG, BMP, TIFF, WEBP

> PNG is recommended for encrypted output since it is lossless. Saving to JPG will apply lossy compression and **break decryption**.

---

## Dependencies

- [Pillow](https://python-pillow.org/) — image I/O
- [NumPy](https://numpy.org/) — fast pixel array operations
