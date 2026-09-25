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
python main.py
```

A window will open. From there:
1. Click **Browse** to select your input image
2. Set the output file path (auto-suggested)
3. Enter an integer **key**
4. Pick a **mode** and **operation** (Encrypt / Decrypt)
5. Click **▶ Run**

The output preview appears instantly on success.

---

## Project Structure

```
SCT_CS_2/
├── main.py          # Everything — encryption logic + GUI
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
