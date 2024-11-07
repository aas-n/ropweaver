import re
import config

def debug_print(message, debug):
    if debug:
        print(message)

def remove_ansi_codes(text):
    ansi_escape = re.compile(r'\x1b\[.*?m')
    return ansi_escape.sub('', text)

def contains_bad_instructions(instructions):
    return any(bad in instructions for bad in config.BAD_INSTRUCTIONS)

def contains_relative_addressing(instructions):
    return bool(re.search(r"\b(eax|ebx|ecx|edx|esi|edi|ebp|esp)\s*[+-]\s*\d+|\b0x[0-9a-fA-F]+\s*[+-]\s*\d+", instructions))

def has_more_push_than_pop(instructions):
    push_count = instructions.count("push")
    pop_count = instructions.count("pop")
    return push_count > pop_count

def contains_hardcoded_address(instructions):
    return bool(re.search(r"0x[0-9a-fA-F]{7,8}", instructions))

def highlight_instructions(instructions):
    return re.sub(config.INSTRUCTION_PATTERN, f"{config.YELLOW}\\1{config.RESET}", instructions)

def contains_bad_bytes(address, bad_bytes):
    hex_address = f"{int(address, 16):08x}"
    chunks = [hex_address[i:i+2] for i in range(0, len(hex_address), 2)] 
    return any(chunk in bad_bytes for chunk in chunks)

def two_complement(value, bits=32):
    """
    Calculate the two's complement of an integer value with a specified bit width.
    
    Parameters:
    - value (int): The integer value to convert.
    - bits (int): The bit width (default is 32 bits).
    
    Returns:
    - int: The two's complement of the given value within the specified bit width.
    """
    if value < 0:
        # If the value is negative, we calculate its two's complement representation
        value = (1 << bits) + value
    else:
        # If the value is positive, mask it to fit within the specified bit width
        value = value & ((1 << bits) - 1)
    return value