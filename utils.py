import re, config


def debug_print(message, debug):
    if debug:
        print(message)

def remove_ansi_codes(text):
    # Supprimer les codes de couleur ANSI pour nettoyer le texte
    ansi_escape = re.compile(r'\x1b\[.*?m')
    return ansi_escape.sub('', text)

def contains_bad_instructions(instructions):
    # Remove bad instructions for ropping (esp alignement, etc)
    return any(bad in instructions for bad in config.BAD_INSTRUCTIONS)

def contains_relative_addressing(instructions):
    # Detects patterns like "reg + offset" or "address + offset"
    return bool(re.search(r"\b(eax|ebx|ecx|edx|esi|edi|ebp|esp)\s*[+-]\s*\d+|\b0x[0-9a-fA-F]+\s*[+-]\s*\d+", instructions))

def has_more_push_than_pop(instructions):
    # Count occurrences of "push" and "pop" in the gadget
    push_count = instructions.count("push")
    pop_count = instructions.count("pop")
    return push_count > pop_count

def contains_hardcoded_address(instructions):
    # Regex pattern to detect hardcoded addresses like 0x5055e138
    return bool(re.search(r"0x[0-9a-fA-F]{7,8}", instructions))

def highlight_instructions(instructions):
    # Highlight all relevant instructions in yellow
    return re.sub(config.INSTRUCTION_PATTERN, f"{config.YELLOW}\\1{config.RESET}", instructions)

def contains_bad_bytes(address, bad_bytes):
    # Remove addresses with bad bytes
    hex_address = f"{int(address, 16):08x}"
    chunks = [hex_address[i:i+2] for i in range(0, len(hex_address), 2)] 
    return any(chunk in bad_bytes for chunk in chunks)
