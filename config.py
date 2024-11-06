from utils import debug_print


RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def configure_colors(no_color, debug):
    global RED, YELLOW, RESET
    if no_color:
        RED = ""
        YELLOW = ""
        RESET = ""
        debug_print("[DEBUG] Colors disabled", debug)

BAD_INSTRUCTIONS = [
    "clts", "hlt", "lmsw", "ltr", "lgdt", "lidt", "lldt", "mov cr", "mov dr",
    "mov tr", "in ", "ins", "invlpg", "invd", "out", "outs", "cli", "sti",
    "popf", "pushf", "int", "iret", "iretd", "swapgs", "wbinvd", "call",
    "jmp", "leave", "ja", "jb", "jc", "je", "jr", "jg", "jl", "jn", "jo",
    "jp", "js", "jz", "lock", "enter", "wait", "asm", "popal", "psubsb",
    "std", "stosd", "les", "aaa", "aam", "salc", "daa", "fcomp", "retf",
    "sldt", "loope", "xlatb", "imule", "fnclex", "retn", "???"
]

INSTRUCTION_PATTERN = r"\b(add|sub|xor|mov|inc|dec|neg|push|pop|xchg|nop|and|or|cmp|leacwde|sete|sbb|shr|test|sal|setne|sar|adc|shl|cld|clc|sahf|rol|movzx|rcl|ror|cdq)\b"

