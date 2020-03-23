# coding=utf-8
import xlrd

def u2s(txt):
    a = txt
    b = []
    for n in a:
        if "a" <= n <= "z":
            b.append(n.upper())
        elif "A" <= n <= "Z":
            b.append(n.lower())
        else:
            b.append(n)
    return ("".join(b))

def table2str(key):
    for i in range(len(key)):
        key[i] = u2s(str(key[i]))
        if key[i].find("."):
            key[i] = key[i].split(".")[0]

def int2bin(n, count):
    b=bin(n).replace("0b","")
    return b.rjust(count,'0')



data = xlrd.open_workbook('dic.xls')

data.sheet_names()
print("sheets：" + str(data.sheet_names()))
table = data.sheet_by_name('Sheet1')

key=table.col_values(2)
table2str(key)

key_thumb=key[0:37]
key_ARM=key[37:76]
print(key_thumb)
print(key_ARM)

value=table.col_values(3)
value1=table.col_values(4)
table2str(value)
table2str(value1)
value_thumb=value[0:37]
value_ARM0=value[37:76]
value_ARM1=value1[37:76]

print(value_ARM0)
print(value_ARM1)
print(value_thumb)


with open("ARM_THUMB_hello","r") as inf, open("ARM_THUMB_hello_compress","w") as outf:
    insn=inf.readlines()
    for item in insn:
        item=item.replace("0x","").replace("\n","")
        size=len(item)
        if(size==8):
            # c2=item[0:2]
            new_item=""
            c_1=int2bin(int(item[0],16),4)
            c_2=int2bin(int(item[1],16),4)
            flag0=c_1+c_2[1:4]
            new_item=new_item+chr(int(flag0,2))
            bit0=c_2[0]
            valueA=""

            for i in reversed(range(6)):
                if (item[2:(2+i)] in key_ARM):
                    # if(i>1):
                    #     print(item)
                    if(bit0=="0"):
                        valueA=value_ARM0[key_ARM.index(item[2:(2 + i)])]
                    else:
                        valueA=value_ARM1[key_ARM.index(item[2:(2 + i)])]

                    new_item =new_item+ chr(int(valueA)) +item[(2+i):8]
                    outf.write(new_item)
                    break
                # else:
                    # print("p")
                    # print(item)
                    # print("\n")

        if(size==4):
            for i in reversed(range(3)):
                if(item[0:i] in key_thumb):
                    # if (i > 1):
                    #     print(item)
                    item=chr(int(value_thumb[key_thumb.index(item[0:i])])) +item[i:4]
                    # item=item.replace(item[0:i],  )
                    outf.write(item)
                    break
                # else:
                #     print("p")
                #     print(item)
                #     print("\n")




