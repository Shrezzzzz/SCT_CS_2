# SCT_CS_2 — PixelCrypt: Image Encryption Tool

A GUI-based image encryption and decryption tool built with Python and Tkinter, developed as Task 02 of the SkillCraft Technology Cyber Security Internship.

## Features

- Encrypt and decrypt images using RGB pixel manipulation
- Three-step encryption: XOR each pixel channel + shuffle pixel positions using a numeric key
- Browse and select input image via file dialog
- Auto-suggested output file path
- Optional numeric encryption key with strength indicator
- Live input and output image previews (Viewport Buffer)
- Threaded processing — UI stays responsive on large images
- Input validation with error messages
- Supports PNG, JPG, JPEG, BMP, TIFF, WEBP
- Cross-platform: macOS, Windows, Linux
- All file handling via `pathlib` — no OS-specific paths

## How It Works

| Step | Encrypt | Decrypt |
|------|---------|---------|
| 1 | XOR each RGB channel byte with `key_seed % 256` | Reverse XOR each channel byte |
| 2 | Shuffle pixel positions using key as RNG seed | Unshuffle pixels using same seed |

**XOR Operation**
```
Encrypted pixel = Original pixel XOR (seed % 256)
Decrypted pixel = Encrypted pixel XOR (seed % 256)
```

XOR is self-reversing — running the same operation again restores the original.

**Pixel Shuffle**
```
Encrypt: shuffle positions using random.seed(key_seed)
Decrypt: reverse the shuffle using the same seed
```

> You must use the **same key** to decrypt that you used to encrypt.
> Always save encrypted output as **PNG** — lossy formats like JPG will corrupt pixel values and break decryption.

## Technologies Used

- Python 3
- Tkinter (GUI — built-in, no install needed)
- Pillow (image I/O)
- NumPy (pixel array operations)
- pathlib (cross-platform file handling)

## Requirements

```
pillow==12.0.0
numpy==2.2.6
```

## Setup

```bash
python3 -m venv venv
source venv/bin/activate        # macOS / Linux
# venv\Scripts\activate         # Windows
pip install -r requirements.txt
```

## How to Run

```bash
python main.py
```

## Usage

**Encrypt**
1. Click **Browse Files** under Source Image
2. Check **Encrypt with Numeric Key** and enter a key (optional)
3. Click **Encrypt Image**
4. Click **Download .enc** to save the encrypted file

**Decrypt**
1. Click **Browse Files** under Encrypted File
2. Check **Same Key Required** and enter the same key you used to encrypt
3. Click **Decrypt Image**
4. Click **Download Restored Image** to save the result

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
