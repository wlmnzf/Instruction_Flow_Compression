from __future__ import print_function
from capstone import *
from capstone.x86 import *
from xprint import to_hex, to_x, to_x_32
import re

path="ARM_hello"
out="ARM_padded"
with open(path, 'r') as f,open(out,"w") as outf:
    text=f.readlines()
    for line in text:
        newline="0x"+line
        outf.write(newline)