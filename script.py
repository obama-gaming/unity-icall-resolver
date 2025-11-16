import idc
import ida_name
import ida_nalt
import idautils
import ida_bytes
import ida_funcs

def read_string(ea):
    if not ea or ea == idc.BADADDR:
        return None
    data = ida_bytes.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C)
    if not data:
        return None
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="ignore")
    return str(data)

def sanitize_name(raw_name):
    raw_name = raw_name.strip()
    if not raw_name:
        return None
    chars = []
    for ch in raw_name:
        if ch.isalnum() or ch == "_":
            chars.append(ch)
        else:
            chars.append("_")
    name = "".join(chars)
    while "__" in name:
        name = name.replace("__", "_")
    name = name.strip("_")
    if not name:
        return None
    if name[0].isdigit():
        name = "_" + name
    return name

def find_icall_add_call():
    target = "il2cpp_add_internal_call"
    strings = idautils.Strings()
    if hasattr(strings, "setup"):
        strings.setup()

    string_ea = idc.BADADDR
    for s in strings:
        if target in str(s):
            string_ea = int(s.ea)
            break

    if string_ea == idc.BADADDR:
        print('[-] Failed to find "il2cpp_add_internal_call" string')
        return idc.BADADDR

    print(f'[+] Found "{target}" string @ 0x{string_ea:016X}')

    icall_global = idc.BADADDR
    init_func_start = idc.BADADDR

    for xref in idautils.XrefsTo(string_ea):
        func = ida_funcs.get_func(xref.frm)
        if not func:
            continue

        ea = xref.frm
        end = func.end_ea
        visited_call = False
        count = 0
        while ea != idc.BADADDR and ea < end and count < 64:
            ea = idc.next_head(ea, end)
            if ea == idc.BADADDR or ea >= end:
                break
            count += 1

            mnem = idc.print_insn_mnem(ea).lower()
            if not visited_call:
                if mnem.startswith("call"):
                    visited_call = True
                continue

            if mnem == "mov":
                if idc.get_operand_type(ea, 0) == idc.o_mem and idc.get_operand_type(ea, 1) == idc.o_reg:
                    if idc.print_operand(ea, 1).lower() == "rax":
                        g = idc.get_operand_value(ea, 0)
                        if g and g != idc.BADADDR:
                            icall_global = g
                            init_func_start = func.start_ea
                            break

        if icall_global != idc.BADADDR:
            break

    if icall_global == idc.BADADDR or init_func_start == idc.BADADDR:
        print("[-] Could not locate il2cpp_add_internal_call")
        return idc.BADADDR

    print(f"[+] Found il2cpp_add_internal_call @ 0x{icall_global:016X}")

    wrapper_ea = idc.BADADDR
    for xref in idautils.XrefsTo(icall_global):
        func = ida_funcs.get_func(xref.frm)
        if not func:
            continue
        if func.start_ea == init_func_start:
            continue
        wrapper_ea = func.start_ea
        break

    if wrapper_ea == idc.BADADDR:
        print("[-] Failed to locate add call wrapper")
        return idc.BADADDR
    
    print(f"[+] Found add call wrapper @ 0x{wrapper_ea:016X}")
    return wrapper_ea

def find_mov_mem_to_reg_rva(func, start_ea, reg_name, max_back=40):
    reg_name = reg_name.lower()
    image_base = ida_nalt.get_imagebase()
    ea = start_ea
    count = 0
    while count < max_back:
        ea = idc.prev_head(ea, func.start_ea)
        if ea == idc.BADADDR or ea < func.start_ea:
            break
        count += 1
        if idc.print_insn_mnem(ea).lower() != "mov":
            continue
        dst = idc.print_operand(ea, 0).lower()
        if dst != reg_name:
            continue
        op_type = idc.get_operand_type(ea, 1)
        if op_type not in (idc.o_mem, idc.o_displ):
            continue
        disp = idc.get_operand_value(ea, 1)
        if disp == 0:
            continue
        if op_type == idc.o_mem and disp >= image_base:
            return disp - image_base
        return disp
    return None

def find_icall_tables(wrapper_func_ea):
    if wrapper_func_ea == idc.BADADDR:
        return []

    tables = []
    func_xrefs = set()
    visited_funcs = set()
    for xref in idautils.XrefsTo(wrapper_func_ea):
        if idc.print_insn_mnem(xref.frm).lower() != "call":
            continue
        func = ida_funcs.get_func(xref.frm)
        if not func:
            continue
        if func.start_ea == wrapper_func_ea:
            continue
        func_xrefs.add(func.start_ea)

    for func_ea in sorted(func_xrefs):
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        start = func.start_ea
        end = func.end_ea

        entry_count = None
        call_ea = None

        ea = start
        while ea != idc.BADADDR and ea < end:
            mnem = idc.print_insn_mnem(ea).lower()

            if mnem == "cmp" and idc.get_operand_type(ea, 1) == idc.o_imm:
                imm = idc.get_operand_value(ea, 1)
                if 0 < imm < 0x1000000:
                    next_ea = idc.next_head(ea, end)
                    if next_ea != idc.BADADDR and next_ea < end:
                        next_mnem = idc.print_insn_mnem(next_ea).lower()
                        if next_mnem.startswith("j"):
                            target = idc.get_operand_value(next_ea, 0)
                            if start <= target < next_ea:
                                entry_count = imm

            elif mnem == "call":
                if idc.get_operand_value(ea, 0) == wrapper_func_ea:
                    call_ea = ea

            ea = idc.next_head(ea, end)

        if not entry_count or entry_count <= 0:
            continue
        if call_ea is None:
            continue

        name_rva = find_mov_mem_to_reg_rva(func, call_ea, "rcx")
        func_rva = find_mov_mem_to_reg_rva(func, call_ea, "rdx")
        if name_rva is None or func_rva is None:
            continue

        key = (func_rva, name_rva, entry_count)
        if key in visited_funcs:
            continue
        visited_funcs.add(key)
        tables.append((start, func_rva, name_rva, entry_count))

    return tables

def rename_icalls_for_table(function_table_rva, name_table_rva, entry_count, seen_targets):
    image_base = ida_nalt.get_imagebase()
    function_table_ea = image_base + function_table_rva
    name_table_ea = image_base + name_table_rva

    renamed = 0

    for index in range(int(entry_count)):
        func_ptr_ea = function_table_ea + index * 8
        name_ptr_ea = name_table_ea + index * 8

        if not ida_bytes.is_loaded(func_ptr_ea) or not ida_bytes.is_loaded(name_ptr_ea):
            continue

        function_ea = ida_bytes.get_qword(func_ptr_ea)
        name_address = ida_bytes.get_qword(name_ptr_ea)

        if not function_ea or not name_address:
            continue
        if function_ea in seen_targets:
            continue

        raw_name = read_string(name_address)
        if not raw_name:
            continue

        new_name = sanitize_name(raw_name)
        if not new_name:
            continue

        if ida_name.set_name(function_ea, new_name, ida_name.SN_NOWARN | ida_name.SN_FORCE):
            seen_targets.add(function_ea)
            renamed += 1
    return renamed

def rename_icalls():
    wrapper_func_ea = find_icall_add_call()
    if wrapper_func_ea == idc.BADADDR:
        return

    tables = find_icall_tables(wrapper_func_ea)
    if not tables:
        print("[-] Found 0 registration tables")
        return

    print(f"[+] Found {len(tables)} registration table(s)")

    seen_targets = set()
    total_renamed = 0
    for idx, (stub_start, func_rva, name_rva, entry_count) in enumerate(tables, 1):
        renamed = rename_icalls_for_table(func_rva, name_rva, entry_count, seen_targets)
        total_renamed += renamed
    print(f"[+] Renamed {total_renamed} functions")

rename_icalls()
