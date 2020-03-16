with open("../X86_hello_padded", "r") as fdata:  
    with open("_X86_legacy", "r") as fleg:
        with open("_X86_prefix", "r") as fpre:
            with open("_X86_opcode", "r") as fopc:
                with open("_X86_modrm", "r") as fmod:
                    	with open("_X86_sib", "r") as fsib:
                            with open("_X86_rest", "r") as frest:
                                data=fdata.readlines()
                                leg=fleg.readlines()
                                pre=fpre.readlines()
                                opcode=fopc.readlines()
                                mod=fmod.readlines()
                                sib=fsib.readlines()
                                rest=frest.readlines()
                                
                                isSuccessful=1
                                print(len(data))
                                for i in range(len(data)):
                                    insn="0x{}{}{}{}{}{}".format(leg[i],pre[i],opcode[i],mod[i],sib[i],rest[i]).replace('\n',"")

                                    if(insn.strip()!=data[i].strip()):
                                        isSuccessful=0
                                        print(i)
                                        print(insn)
                                        print(data[i])
                                
                                if(isSuccessful):
                                    print("Succeessful!\n")

