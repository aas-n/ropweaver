import config

def load_gadgets(filename):
    with open(filename, "r") as file:
        return [line.strip() for line in file if line.strip()]

def display_gadget_categories(categories, limit):
    for category, gadgets in categories.items():
        # Display category name in red
        print(f"\n{config.RED}{category}{config.RESET}")
        for gadget in gadgets[:limit]:
            print(f"- {gadget}")
