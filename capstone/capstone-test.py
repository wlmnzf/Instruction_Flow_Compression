from capstone import *
import re
md = Cs(CS_ARCH_X86, CS_MODE_64)

with open('X86_hello', 'r') as f:
	data=f.readlines()
	with open("X86_hello_ASM", "w") as fd:
		for inst in data:
			inst=inst.replace("0x","")
			pattern = re.compile('.{2}')
			inst='|'.join(pattern.findall(inst))
			inst=list(inst.split('|'))
			for i,val in enumerate(inst):
				inst[i]=int(val,16)
			inst=bytes(inst)
			print(inst)
			for i in md.disasm(inst, 0x1000):
				fd.write("0x%x:\t%s\t%s\n" %(i.address, i.mnemonic, i.op_str))
			







