# SCT_CS_2 — Image Encryption Tool

A GUI-based image encryption and decryption tool built with Python and Tkinter, developed as Task 02 of the SkillCraft Technology Cyber Security Internship.

## Features

- Encrypt and decrypt images using pixel manipulation
- Three encryption modes — XOR, Pixel Swap, and Combined
- Browse and select input image via file dialog
- Auto-suggested output file path
- User-defined integer encryption key
- Live input and output image previews
- Threaded processing — UI stays responsive on large images
- Input validation with error messages
- Supports PNG, JPG, JPEG, BMP, TIFF, WEBP
- Dark themed UI

## How It Works

Three encryption modes are available:

| Mode | Description | Reversible |
|------|-------------|------------|
| XOR | XORs every pixel channel value with `key % 256` | ✅ Self-reversing |
| Swap | Shuffles pixel positions using the key as an RNG seed | ✅ With same key |
| Combined | XOR first, then shuffle — strongest scrambling (default) | ✅ With same key |

### XOR Mode

```
Encrypted = Pixel XOR (Key mod 256)
Decrypted = Encrypted XOR (Key mod 256)
```

XOR is self-reversing — running the same operation again restores the original.

### Swap Mode

```
Encrypt: shuffle pixel positions using random.seed(key)
Decrypt: reverse the shuffle using the same seed
```

### Combined Mode

```
Encrypt: XOR → Swap
Decrypt: Unshuffle → XOR
```

> **Important:** You must use the **same key and mode** to decrypt that you used to encrypt. Always save encrypted output as **PNG** — lossy formats like JPG will corrupt pixel values and break decryption.

## Technologies Used

- Python 3
- Tkinter (GUI)
- Pillow (image I/O)
- NumPy (pixel array operations)

## Requirements

```
pillow==12.0.0
numpy==2.2.6
```

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## How to Run

```bash
python main.py
```

## Usage

1. Click **Browse** next to INPUT IMAGE to select your image
2. The output path is auto-suggested — change it if needed
3. Enter an integer **Encryption Key** (e.g. 42, 1337)
4. Select a **Mode** — XOR / Swap / Combined
5. Select the **Operation** — Encrypt or Decrypt
6. Click **▶ Run**
7. The output image preview appears on success

## Project Structure

```
SCT_CS_2/
├── main.py          # Main application (encryption logic + GUI)
├── requirements.txt # Python dependencies
└── README.md        # Project documentation
```

## Internship

Organisation: SkillCraft Technology  
Domain: Cyber Security  
Task: 02 — Image Encryption Tool
