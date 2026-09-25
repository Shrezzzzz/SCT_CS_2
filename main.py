"""
Image Encryption Tool — CLI
Usage examples:
  python main.py encrypt photo.png encrypted.png --key 42
  python main.py decrypt encrypted.png restored.png --key 42 --mode xor
  python main.py encrypt photo.png encrypted.png --key 1337 --mode swap
"""

import argparse
import sys
import os
from encryptor import process_image, MODES


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="image-encryptor",
        description="🔐 Simple image encryption tool using pixel manipulation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  xor       XOR every pixel channel with the key (fast, self-reversing)
  swap      Shuffle pixel positions using the key as RNG seed
  combined  XOR then shuffle — strongest scrambling (default)

Examples:
  python main.py encrypt input.png output.png --key 42
  python main.py decrypt output.png restored.png --key 42
  python main.py encrypt input.png out.png --key 999 --mode xor
        """,
    )

    parser.add_argument(
        "operation",
        choices=["encrypt", "decrypt"],
        help="Whether to encrypt or decrypt the image.",
    )
    parser.add_argument(
        "input",
        help="Path to the input image (PNG, JPG, BMP, etc.).",
    )
    parser.add_argument(
        "output",
        help="Path where the result image will be saved.",
    )
    parser.add_argument(
        "--key",
        type=int,
        required=True,
        help="Integer encryption key. Use the same key to decrypt.",
    )
    parser.add_argument(
        "--mode",
        choices=list(MODES.keys()),
        default="combined",
        help="Encryption mode: xor | swap | combined (default: combined).",
    )

    return parser


def validate_args(args: argparse.Namespace) -> None:
    if not os.path.isfile(args.input):
        print(f"[ERROR] Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    out_dir = os.path.dirname(os.path.abspath(args.output))
    if not os.path.isdir(out_dir):
        print(f"[ERROR] Output directory does not exist: {out_dir}", file=sys.stderr)
        sys.exit(1)

    supported = {".png", ".jpg", ".jpeg", ".bmp", ".tiff", ".webp"}
    ext = os.path.splitext(args.input)[1].lower()
    if ext not in supported:
        print(f"[WARN] '{ext}' may not be fully supported. Proceeding anyway.")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    validate_args(args)

    print()
    print("╔══════════════════════════════════╗")
    print("║   Image Encryption Tool v1.0     ║")
    print("╚══════════════════════════════════╝")
    print()

    try:
        process_image(
            input_path=args.input,
            output_path=args.output,
            key=args.key,
            mode=args.mode,
            operation=args.operation,
        )
        print()
        print(f"  ✅  Done! '{args.operation.capitalize()}ion' complete.")
        print()
    except Exception as e:
        print(f"\n[ERROR] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
