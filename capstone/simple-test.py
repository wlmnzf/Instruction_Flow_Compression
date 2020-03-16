from capstone import *

# CODE = b"\x48\x89\xe7"
CODE = (0x48, 0x89, 0xe7)
CODE = bytes(CODE) 
print(CODE)

md = Cs(CS_ARCH_X86, CS_MODE_64)
for i in md.disasm(CODE, 0x1000):
    print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
