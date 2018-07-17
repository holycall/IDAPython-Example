# IDAPython Example

## Get image base, end address, and size
```Python
image_base = idaapi.get_imagebase()
segs = list(Segments())
image_end = SegEnd(segs[-1])
image_size = SegEnd(segs[-1]) - image_base
```

## Get function start address and end address
```Python
ea = idc.ScreenEA()
fn = idaapi.get_func(ea)
fn_start_ea = fn.start_ea
fn_end_ea = fn.end_ea
```

## Get an instruction size
```Python
ItemSize(ea)
```

## Disassemble one instruction
```Python
GetDisasm(ea)
```

## Get operand string from an instruction at an address
```Python
GetOpnd(ea, 0)
GetOpnd(ea, 1)
```

## Get operand value from an instruction at an address
```Python
GetOperandValue(ea, 0)
GetOperandValue(ea, 1)
```

## Get a string at an address in a static image
```Python
def get_string(ea):
    out = ""
    while True:
        byt = idc.Byte(ea)
        if byt != 0:
            out += chr(byt)
        else:
            break
        ea += 1
    return out
```
