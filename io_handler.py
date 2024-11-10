import config
import re

def load_gadgets(filename):
    with open(filename, "r") as file:
        lines = [line.strip() for line in file if line.strip()]

    # Check if it's a Windows output by looking for the typical header line
    if any("Trying to open" in line for line in lines):
        # Skip lines until we find the first gadget line that matches an address format
        lines = [line for line in lines if re.match(r"0x[0-9a-fA-F]+:", line)]

    return lines

def display_gadget_categories(categories, limit):
    for category, gadgets in categories.items():
        # Display category name in red
        print(f"\n{config.RED}{category}{config.RESET}")
        for gadget in gadgets[:limit]:
            print(f"- {gadget}")

def display_chain(gadgets):
    for gadget in gadgets:
        print(gadget)
    print()