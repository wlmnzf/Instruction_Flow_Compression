path="/media/william/000B4BAB0003D134/WSL/compress/capstone/X86_hello"
out="/media/william/000B4BAB0003D134/WSL/compress/capstone/X86_hello_padded"

with open(out, 'w') as of:   
    with open(path, 'r') as f:
        data=f.readlines()
        for inst in data:
            inst=inst.replace("0x","").replace('\n',"")
            if(len(inst)%2!=0):
                print(inst)
                inst='0'+inst
            of.write("0x"+inst+"\n")
            