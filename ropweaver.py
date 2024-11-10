import argparse
from config import configure_colors
from utils import debug_print
from io_handler import load_gadgets, display_gadget_categories, display_chain
from gadget_classifier import classify_gadgets
from semantic_finder import find_semantic_gadgets

def banner():
    print(r"							                         ")
    print(r"  _____                                              ")
    print(r" |  __ \                                             ")
    print(r" | |__) |___  _ ____      _____  __ ___   _____ _ __ ")
    print(r" |  _  // _ \| '_ \ \ /\ / / _ \/ _` \ \ / / _ \ '__|")
    print(r" | | \ \ (_) | |_) \ V  V /  __/ (_| |\ V /  __/ |   ")
    print(r" |_|  \_\___/| .__/ \_/\_/ \___|\__,_| \_/ \___|_|   ")
    print(r"             | |                                     ")
    print(r"             |_|              @aas_s3curity          ")
    print(r"							                         ")

def main():
    parser = argparse.ArgumentParser(description="Classify and chain ROP gadgets.")
    parser.add_argument("filename", help="The file containing the list of gadgets.")
    parser.add_argument("-b", "--bad-bytes", help="Bad bytes (e.g., '00 0a 0b 0d').", default="")
    parser.add_argument("-c", "--no-color", action="store_true", help="Disable colored output.")
    parser.add_argument("-l", "--limit", type=int, default=None, help="Limit the number of gadgets displayed per category.")
    parser.add_argument("-s", "--semantic", help="Semantic instruction, e.g., 'eax <- ecx'")
    parser.add_argument("-a", "--virtualaddress", help="The virtual address of the module in hexadecimal (-a 0x10000000).")
    parser.add_argument("-v", "--debug", action="store_true", help="Enable debug output.")
    args = parser.parse_args()

    if args.semantic or args.no_color:
        configure_colors(True, args.debug)

    debug_print(f"[DEBUG] Loading gadgets from {args.filename}", args.debug)
    bad_bytes = args.bad_bytes.split()
    bad_bytes = [byte.lower() for byte in bad_bytes if len(byte) == 2 and all(c in "0123456789abcdef" for c in byte.lower())]
    gadget_list = load_gadgets(args.filename)
    categories = classify_gadgets(gadget_list, bad_bytes, args.virtualaddress, args.debug)

    if args.semantic:
        semantic_gadgets = find_semantic_gadgets(categories, args.semantic, args.debug)
        display_chain(semantic_gadgets)
    else:
        display_gadget_categories(categories, args.limit)

if __name__ == "__main__":
    banner()
    main()