import lzma

with open('_X86_modrm', 'r') as f:
	data=f.read().encode('utf-8') 
	with lzma.open("_X86_modrm.xz", "w") as fd:
		fd.write(data)