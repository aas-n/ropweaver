import re
from utils import remove_ansi_codes, debug_print


def find_semantic_gadgets(categories, semantic, debug):
    # Parse the semantic input, e.g., "eax <-> ecx", "eax <- [ebx]", "[eax] <- ecx", "eax <- 0", "eax++", "eax--", "neg eax", "eax + ebx", "eax - ebx", or >
    debug_print(f"[DEBUG] Processing semantic: {semantic}", debug)
    match = (
        re.match(r"(\w+)\s*<->\s*(\w+)", semantic) or  # For swaps like "eax <-> ecx"
        re.match(r"(\w+)\s*<-\s*\[(\w+)\]", semantic) or  # For load from memory like "eax <- [ebx]"
        re.match(r"\[(\w+)\]\s*<-\s*(\w+)", semantic) or  # For store to memory like "[eax] <- ecx"
        re.match(r"(\w+)\s*<-\s*(\w+)", semantic) or  # For register moves like "eax <- ecx"
        re.match(r"(\w+)\s*<-\s*0", semantic) or  # For zeroing a register like "eax <- 0"
        re.match(r"(\w+)\s*\+\+", semantic) or  # For incrementing a register like "eax++"
        re.match(r"(\w+)\s*--", semantic) or  # For decrementing a register like "eax--"
        re.match(r"neg\s+(\w+)", semantic) or  # For negating a register like "neg eax"
        re.match(r"(\w+)\s*\+\s*(\w+)", semantic) or  # For addition like "eax + ebx"
        re.match(r"(\w+)\s*-\s*(\w+)", semantic) or  # For subtraction like "eax - ebx"
        re.match(r"pop\s+(\w+)", semantic)  # For pop register like "pop eax"
    )

    if not match:
        debug_print("[DEBUG] Invalid semantic format.", debug)
        return []

    results = []


    def find_shortest_gadget(categories, category, pattern):
        debug_print(f"[DEBUG] Using pattern: {pattern} in category: {category}", debug)
        shortest_gadget = None
        min_instructions = float('inf')

        # Vérifie si la catégorie existe dans les gadgets
        if category not in categories:
            debug_print(f"[DEBUG] Category '{category}' not found.", debug)
            return None

        for gadget in categories[category]:
            # Nettoie le gadget en supprimant les codes de couleur ANSI
            clean_gadget = remove_ansi_codes(gadget)
            debug_print(f"[DEBUG] Checking gadget: {clean_gadget} with pattern: {pattern}", debug)

            # Vérifie si le gadget correspond au pattern
            if re.search(pattern, clean_gadget):
                # Compte le nombre d'instructions pour trouver le gadget le plus court
                instruction_count = clean_gadget.count(";")
                if instruction_count < min_instructions:
                    min_instructions = instruction_count
                    shortest_gadget = gadget
                    debug_print(f"[DEBUG] New shortest gadget found: {shortest_gadget} with {instruction_count} instructions", debug)

        return shortest_gadget


    # Processing each case with the appropriate category and pattern
    if "pop" in semantic:
        reg = match.groups()[0]
        debug_print(f"[DEBUG] Looking for a way to pop into {reg}", debug)
        pop_gadget = find_shortest_gadget(categories, ".: POP gadgets :.", rf".*pop {reg}.* ret;?")
        if pop_gadget:
            results.append(pop_gadget)
        else:
            debug_print(f"[DEBUG] No pop gadget found for {reg}.", debug)

    elif "] <- " in semantic:
        dest_addr_reg, src_reg = match.groups()
        debug_print(f"[DEBUG] Looking for a way to set [{dest_addr_reg}] <- {src_reg}", debug)
        store_gadget = find_shortest_gadget(categories, ".: [REG1] <- REG2 gadgets :.", rf".*mov (dword ptr )?\[{dest_addr_reg}\], {src_reg}.* ret;?")
        if store_gadget:
            results.append(store_gadget)
        else:
            debug_print(f"[DEBUG] No store gadget found for [{dest_addr_reg}] <- {src_reg}.", debug)

    elif "<->" in semantic:
        reg1, reg2 = match.groups()
        debug_print(f"[DEBUG] Looking for a way to swap {reg1} and {reg2}", debug)
        swap_gadget = find_shortest_gadget(categories, ".: REG1 <-> REG2 gadgets :.", rf".*xchg {reg1}, {reg2}.* ret;?|.*xchg {reg2}, {reg1}.* ret;?", args.debug)
        if swap_gadget:
            results.append(swap_gadget)
        else:
            debug_print(f"[DEBUG] No direct swap gadget found for {reg1} <-> {reg2}.", debug)

    elif " <- [" in semantic:
        dest_reg, src_reg = match.groups()
        debug_print(f"[DEBUG] Looking for a way to set {dest_reg} <- [{src_reg}]", debug)
        load_gadget = find_shortest_gadget(categories, ".: REG1 <- [REG2] gadgets :.", rf".*mov {dest_reg}, (dword ptr )?\[{src_reg}\].* ret;?")
        if load_gadget:
            results.append(load_gadget)
        else:
            debug_print("[DEBUG] No direct load gadget found for memory read.", debug)

    elif " <- 0" in semantic:
        reg = match.groups()[0]
        debug_print(f"[DEBUG] Looking for a way to zero {reg}", debug)
        zero_gadget = find_shortest_gadget(categories, ".: REG <- 0 gadgets :.", rf".*xor {reg}, {reg};.* ret;?")
        if zero_gadget:
            results.append(zero_gadget)
        else:
            debug_print(f"[DEBUG] No zeroing gadget found for {reg}.", debug)

    elif " <- " in semantic and "[" not in semantic:
        dest_reg, src_reg = match.groups()
        debug_print(f"[DEBUG] Looking for a way to set {dest_reg} <- {src_reg}", debug)
        move_gadget = find_shortest_gadget(categories, ".: REG1 <- REG2 gadgets :.", rf".*mov {dest_reg}, {src_reg}.* ret;?")
        if move_gadget:
            results.append(move_gadget)
        else:
            debug_print(f"[DEBUG] No direct move gadget found for {dest_reg} <- {src_reg}.", debug)

    elif "++" in semantic:
        reg = match.groups()[0]
        debug_print(f"[DEBUG] Looking for a way to increment {reg}", debug)
        inc_gadget = find_shortest_gadget(categories, ".: REG++ gadgets :.", rf".*inc {reg}.* ret;?")
        if inc_gadget:
            results.append(inc_gadget)
        else:
            debug_print(f"[DEBUG] No increment gadget found for {reg}.", debug)

    elif "--" in semantic:
        reg = match.groups()[0]
        debug_print(f"[DEBUG] Looking for a way to decrement {reg}", debug)
        dec_gadget = find_shortest_gadget(categories, ".: REG-- gadgets :.", rf".*dec {reg}.* ret;?")
        if dec_gadget:
            results.append(dec_gadget)
        else:
            debug_print(f"[DEBUG] No decrement gadget found for {reg}.", debug)

    elif "neg" in semantic:
        reg = match.groups()[0]
        debug_print(f"[DEBUG] Looking for a way to negate {reg}", debug)
        neg_gadget = find_shortest_gadget(categories, ".: NEG gadgets :.", rf".*neg {reg}.* ret;?")
        if neg_gadget:
            results.append(neg_gadget)
        else:
            debug_print(f"[DEBUG] No negation gadget found for {reg}.", debug)

    elif " + " in semantic:
        reg1, reg2 = match.groups()
        debug_print(f"[DEBUG] Looking for a way to add {reg2} to {reg1}", debug)
        add_gadget = find_shortest_gadget(categories, ".: REG1 + REG2 gadgets :.", rf".*add {reg1}, {reg2}.* ret;?")
        if add_gadget:
            results.append(add_gadget)
        else:
            debug_print(f"[DEBUG] No addition gadget found for {reg1} + {reg2}.", debug)

    elif " - " in semantic:
        reg1, reg2 = match.groups()
        debug_print(f"[DEBUG] Looking for a way to subtract {reg2} from {reg1}", debug)
        sub_gadget = find_shortest_gadget(categories, ".: REG1 - REG2 gadgets :.", rf".*sub {reg1}, {reg2}.* ret;?")
        if sub_gadget:
            results.append(sub_gadget)
        else:
            debug_print(f"[DEBUG] No subtraction gadget found for {reg1} - {reg2}.", debug)

    return results

def try_find_intermediate_chain_from_memory(categories, dest_reg, src_reg):
    chain = []
    intermediate_category = ".: REG1 <- [REG2] gadgets :."

    # Parcours des registres temporaires pour charger [src_reg] dans dest_reg
    for reg in ["eax", "ebx", "ecx", "edx", "esi", "edi"]:
        if reg == dest_reg or reg == src_reg:
            continue

        # Étape 1 : Charger [src_reg] dans un registre temporaire
        first_move_pattern = rf"mov {reg}, (dword ptr )?\[{src_reg}\];.* ret;?"
        found_first = False
        for gadget in categories.get(intermediate_category, []):
            if re.search(first_move_pattern, remove_ansi_codes(gadget)):
                debug_print(f"[DEBUG] Found first move in chain: {gadget}", debug)
                chain.append(gadget)
                found_first = True
                break

        if not found_first:
            debug_print(f"[DEBUG] No first move found for [{src_reg}] -> {reg}", debug)
            continue

        # Étape 2 : Transférer la valeur du registre temporaire vers dest_reg
        second_move_pattern = rf"mov {dest_reg}, {reg};.* ret;?"
        found_second = False
        for gadget in categories.get(".: REG1 <- REG2 gadgets :.", []):
            if re.search(second_move_pattern, remove_ansi_codes(gadget)):
                debug_print(f"[DEBUG] Found second move in chain: {gadget}", debug)
                chain.append(gadget)
                found_second = True
                return chain  # Retourne la chaîne complète dès qu'elle est trouvée

        if not found_second:
            debug_print(f"[DEBUG] No second move found for {reg} -> {dest_reg}", debug)
            chain.clear()  # Réinitialise la chaîne si la deuxième étape n'est pas trouvée

    return []
