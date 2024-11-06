import re
from utils import contains_bad_instructions, contains_bad_bytes, contains_relative_addressing, has_more_push_than_pop, contains_hardcoded_address, highlight_instructions

from utils import remove_ansi_codes
import config

def classify_gadget(gadget, bad_bytes):
    classifications = []
    address, instructions = gadget.split("  # ")

    instructions = re.sub(r"\bret\b(?!;)", "ret;", instructions)

    if (contains_bad_instructions(instructions) or contains_bad_bytes(address, bad_bytes) or 
        contains_relative_addressing(instructions) or has_more_push_than_pop(instructions) or contains_hardcoded_address(instructions)):
        return classifications  # Skip gadgets with bad instructions, ESP impact, relative addressing, or excessive push

    # Apply highlighting to the entire instruction set
    highlighted_instructions = highlight_instructions(instructions)

    # Add gadgets to categories with highlighted instructions
    if re.match(r".*mov \[e..\], e..;.* ret;?|.*mov dword ptr \[e..\], e..;.* ret;?", instructions):
        classifications.append((".: [REG1] <- REG2 gadgets :.", address, highlighted_instructions))
    if re.match(r".*mov e.., \[e..\];.* ret;?|.*mov e.., dword ptr \[e..\];.* ret;?", instructions):
        classifications.append((".: REG1 <- [REG2] gadgets :.", address, highlighted_instructions))
    if re.match(r".*mov e.., e..;.* ret;?", instructions):
        classifications.append((".: REG1 <- REG2 gadgets :.", address, highlighted_instructions))
    if re.match(r".*xchg e.., e..;.* ret;?", instructions):
        classifications.append((".: REG1 <-> REG2 gadgets :.", address, highlighted_instructions))
    if re.match(r".*inc e..;.* ret;?", instructions):
        classifications.append((".: REG++ gadgets :.", address, highlighted_instructions))
    if re.match(r".*dec e..;.* ret?;", instructions):
        classifications.append((".: REG-- gadgets :.", address, highlighted_instructions))
    if re.match(r".*add e.., e..;.* ret;?", instructions):
        classifications.append((".: REG1 + REG2 gadgets :.", address, highlighted_instructions))
    if re.match(r".*sub e.., e..;.* ret;?", instructions):
        classifications.append((".: REG1 - REG2 gadgets :.", address, highlighted_instructions))
    if re.match(r".*neg e..;.* ret;?", instructions):
        classifications.append((".: NEG gadgets :.", address, highlighted_instructions))
    if re.match(r".*xor e.., e..;.* ret;?", instructions):
        classifications.append((".: XOR REG1, REG2 gadgets :.", address, highlighted_instructions))
    if re.match(r".*push e..;.* pop e..;.* ret;?", instructions):
        classifications.append((".: PUSH/POP gadgets :.", address, highlighted_instructions))
    if re.match(r".*pop e..; ret;?", instructions):
        classifications.append((".: POP gadgets :.", address, highlighted_instructions))
    if re.match(r".*xor\s+(e[abcdsix]{2}),\s*\1;\s*ret;|.*mov e.., 0x0x0000000[01];.* ret;?", instructions):
        classifications.append((".: REG <- 0 gadgets :.", address, highlighted_instructions))

    return classifications

def classify_gadgets(gadget_list, bad_bytes):
    categories = {
        ".: [REG1] <- REG2 gadgets :.": set(),
        ".: REG1 <-> REG2 gadgets :.": set(),
        ".: REG1 <- REG2 gadgets :.": set(),
        ".: REG++ gadgets :.": set(),
        ".: REG-- gadgets :.": set(),
        ".: REG1 + REG2 gadgets :.": set(),
        ".: REG1 - REG2 gadgets :.": set(),
        ".: NEG gadgets :.": set(),
        ".: XOR REG1, REG2 gadgets :.": set(),
        ".: PUSH/POP gadgets :.": set(),
        ".: POP gadgets :.": set(),
        ".: REG <- 0 gadgets :.": set(),
        ".: REG1 <- [REG2] gadgets :.": set(),
    }

    seen_instructions = {category: set() for category in categories}

    for gadget in gadget_list:
        classifications = classify_gadget(gadget, bad_bytes)
        for category, address, highlighted_instruction in classifications:
            #Separe les instructions de l'adresse pour la deduplication
            instruction_only = highlighted_instruction.split("#", 1)[-1].strip()

            # Format the output as specified
            if instruction_only not in seen_instructions[category]:
               formatted_gadget = f"rop += pack(\"<L\", {address})       # {highlighted_instruction}"
               categories[category].add(formatted_gadget)
               seen_instructions[category].add(instruction_only)

    # Convert sets back to lists for consistent display
    for category in categories:
        categories[category] = sorted(categories[category], key=lambda gadget: gadget.count(";")) # compte le nombre d'instructions en fonction des ;

    return categories
