# IDAPython 7.5 Example

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

