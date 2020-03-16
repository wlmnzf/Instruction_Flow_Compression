import lzma

with open('X86_hello', 'r') as f:
	data=f.read().encode('utf-8') 
	with lzma.open("X86_hello.xz", "w") as fd:
		fd.write(data)