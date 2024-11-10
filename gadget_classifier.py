import re
from utils import contains_bad_instructions, contains_bad_bytes, contains_relative_addressing, has_more_push_than_pop, contains_hardcoded_address, highlight_instructions
from utils import remove_ansi_codes
import config


def classify_gadget(gadget, bad_bytes, virtualAddress):
    classifications = []
    
    # Detect format based on separator
    if ": " in gadget:
        # Windows format
        address, instructions = gadget.split(": ", 1)
        # Replace " ; " with "; " for consistent instruction parsing
        instructions = instructions.replace(" ; ", "; ")
        # Remove "(x found)" suffix if present
        instructions = re.sub(r"\s*\(\d+ found\)$", "", instructions)
        # Standardize 'ret' variations to 'ret;' or 'ret <offset>;'
        instructions = re.sub(r"\bret\s*(0x[0-9a-fA-F]+)?\s*;?", lambda m: f"ret {m.group(1)};" if m.group(1) else "ret;", instructions)
    else:
        # Linux format
        address, instructions = gadget.split("  # ", 1)
        # Standardize 'ret' variations to 'ret;' or 'ret <offset>;'
        instructions = re.sub(r"\bret\s*(0x[0-9a-fA-F]+)?\s*;?", lambda m: f"ret {m.group(1)};" if m.group(1) else "ret;", instructions)

    if virtualAddress is not None:
        address = str(hex(int(address, 16) - int(virtualAddress, 16)))

    # Skip gadgets with undesired instructions or characteristics
    if (contains_bad_instructions(instructions) or contains_relative_addressing(instructions) or has_more_push_than_pop(instructions) or contains_hardcoded_address(instructions) or contains_bad_bytes(address, bad_bytes)):
        return classifications

    # Apply highlighting to the entire instruction set
    highlighted_instructions = highlight_instructions(instructions)

    # Add gadgets to categories with highlighted instructions
    if re.match(r".*(mov\s+\[\s*(e[abcdsix]{2})\s*\],\s*(e[abcdsix]{2}).*?ret;|mov\s+dword\s+ptr\s+\[\s*(e[abcdsix]{2})\s*\],\s*(e[abcdsix]{2}).*?ret;)", instructions):
        classifications.append((".: [REG1] <- REG2 gadgets :.", address, highlighted_instructions))
    if re.match(r".*(mov\s+(e[abcdsix]{2}),\s*\[\s*(e[abcdsix]{2})\s*\].*?ret;|mov\s+dword\s+ptr\s+(e[abcdsix]{2}),\s*\[\s*(e[abcdsix]{2})\s*\].*?ret;)", instructions):
        classifications.append((".: REG1 <- [REG2] gadgets :.", address, highlighted_instructions))
    if re.match(r".*(mov\s+(e[abcdsix]{2}),\s*(e[abcdsix]{2}).*?ret;|mov\s+dword\s+ptr\s+(e[abcdsix]{2}),\s*(e[abcdsix]{2}).*?ret;|push\s+(e[abcdsix]{2});.*?pop\s+(e[abcdsix]{2}).*?ret;)", instructions):
        classifications.append((".: REG1 <- REG2 gadgets :.", address, highlighted_instructions))
    if re.match(r".*xchg\s+(e[abcdsix]{2}),\s*(e[abcdsix]{2}).*?ret;", instructions):
        classifications.append((".: REG1 <-> REG2 gadgets :.", address, highlighted_instructions))
    if re.match(r".*inc\s+(e[abcdsix]{2}).*?ret;", instructions):
        classifications.append((".: REG++ gadgets :.", address, highlighted_instructions))
    if re.match(r".*dec\s+(e[abcdsix]{2}).*?ret;", instructions):
        classifications.append((".: REG-- gadgets :.", address, highlighted_instructions))
    if re.match(r".*add\s+(e[abcdsix]{2}),\s*(e[abcdsix]{2}).*?ret;", instructions):
        classifications.append((".: REG1 + REG2 gadgets :.", address, highlighted_instructions))
    if re.match(r".*sub\s+(e[abcdsix]{2}),\s*(e[abcdsix]{2}).*?ret;", instructions):
        classifications.append((".: REG1 - REG2 gadgets :.", address, highlighted_instructions))
    if re.match(r".*neg\s+(e[abcdsix]{2}).*?ret;", instructions):
        classifications.append((".: NEG gadgets :.", address, highlighted_instructions))
    if re.match(r".*xor\s+(e[abcdsix]{2}),\s*(e[abcdsix]{2}).*?ret;", instructions):
        classifications.append((".: XOR REG1, REG2 gadgets :.", address, highlighted_instructions))
    if re.match(r".*push\s+(e[abcdsix]{2}).*?pop\s+\1.*?ret;", instructions):
        classifications.append((".: PUSH/POP gadgets :.", address, highlighted_instructions))
    if re.match(r"(.*pop \w+;.*?ret;)", instructions):
        classifications.append((".: POP gadgets :.", address, highlighted_instructions))
    if re.match(r".*(xor\s+(e[abcdsix]{2}),\s*\2;.*?ret;|mov\s+(e[abcdsix]{2}),\s*(0x0+|0);.*?ret;)", instructions):
        classifications.append((".: REG <- 0 gadgets :.", address, highlighted_instructions))

    return classifications



def classify_gadgets(gadget_list, bad_bytes, virtualAddress):
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
        classifications = classify_gadget(gadget, bad_bytes, virtualAddress)
        for category, address, highlighted_instruction in classifications:
            instruction_only = highlighted_instruction.split("#", 1)[-1].strip()

            if instruction_only not in seen_instructions[category]:
                if virtualAddress is not None:
                    formatted_gadget = f"rop += pack(\"<L\", moduleAddress + {address})       # {highlighted_instruction}"
                else:
                    formatted_gadget = f"rop += pack(\"<L\", {address})       # {highlighted_instruction}"
                categories[category].add(formatted_gadget)
                seen_instructions[category].add(instruction_only)

    for category in categories:
        categories[category] = sorted(categories[category], key=lambda gadget: gadget.count(";"))

    return categories
