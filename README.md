# IDAPython 7.4 Example

## Get image base, end address, and size
```Python
image_base = idaapi.get_imagebase()
segs = list(Segments())
image_end = idc.get_segm_end(segs[-1])
image_size = idc.get_segm_end(segs[-1]) - image_base
```

## Get function start address and end address
```Python
ea = idc.get_screen_ea()
fn = idaapi.get_func(ea)
fn_start_ea = fn.start_ea
fn_end_ea = fn.end_ea
```

## Get an instruction size
```Python
get_item_size(ea)
```

## Disassemble one instruction
```Python
GetDisasm(ea)
```

## Get operand string from an instruction at an address
```Python
print_operand(ea, 0)
print_operand(ea, 1)
```

## Get operand value from an instruction at an address
```Python
get_operand_value(ea, 0)
get_operand_value(ea, 1)
```

## Get a string at an address in a static image
```Python
def get_string(ea):
    out = ""
    while True:
        byt = idc.get_wide_byte(ea)
        if byt != 0:
            out += chr(byt)
        else:
            break
        ea += 1
    return out
```

## Get Entrypoint
```Python
ida_ida.inf_get_start_ea()	
```

## Print instructions in a function using capstone disassembler
```Python
import ida_funcs
import ida_kernwin
import idautils
import ida_bytes
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

ea = ida_kernwin.get_screen_ea()
fn = ida_funcs.get_func(ea)

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

for ea in idautils.Heads(fn.start_ea, fn.end_ea):
    ins = idautils.DecodeInstruction(ea)
    ins_size = ins.size
    byts = ida_bytes.get_bytes(ea, ins_size)
    byts_str = ''
    for byt in byts:
        byts_str += f'{byt:02X}'
    cs_ins_gen = md.disasm(byts, ea)
    for cs_ins in cs_ins_gen:
        mne = cs_ins.mnemonic
        op_str = cs_ins.op_str
        print(f'{ea:016X} {mne} {op_str} # {byts_str}')
```

## Get cross references of stack variables in a function
```Python
import idc, ida_ua, idautils, ida_bytes, ida_funcs
from typing import Dict

def find_stack_members(func_ea):
    members = {}
    base = None
    frame = idc.get_func_attr(func_ea, idc.FUNCATTR_FRAME)
    for frame_member in idautils.StructMembers(frame):
        member_offset, member_name, _ = frame_member
        members[member_offset] = member_name
        if member_name == ' r':
            base = member_offset
    if not base:
        raise ValueError("Failed identifying the stack's base address using the return address hidden stack member")
    return members, base


def find_stack_xrefs(func_offset) -> Dict[str, list[int, int]]:
    """
    Get cross references of each stack variables.
    :param func_offset:
    :return: variable name to list of an instruction address and its operand number.
    """
    func_ea = ida_funcs.get_func(func_offset).start_ea
    result = dict()
    members, stack_base = find_stack_members(func_ea)
    for func_item in idautils.FuncItems(func_ea):
        flags = ida_bytes.get_full_flags(func_item)
        stkvar = 0 if ida_bytes.is_stkvar0(flags) else 1 if ida_bytes.is_stkvar1(flags) else None
        if stkvar is None:
            continue
        insn = ida_ua.insn_t()
        ida_ua.decode_insn(insn, func_item)
        op = insn.ops[stkvar]
        stack_offset = op.addr + idc.get_spd(func_item) + stack_base
        member = members[stack_offset]
        result.setdefault(member, []).append((func_item, stkvar))
    return result


if __name__ == "__main__":
    result = find_stack_xrefs(idc.here())
    for member, lst in result.items():
        print(f"{member}")
        for addr, opn in lst:
            print(f'{addr:x} op#:{opn}')
```
