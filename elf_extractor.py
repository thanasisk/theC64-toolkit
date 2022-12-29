#!/usr/bin/env python3
import os
import sys
from elftools.elf.elffile import ELFFile

ELF_OFFSET=0x58 # grabbed from binwalk

if len(sys.argv) != 2:
    print(sys.argv[0] + " firmware")
    sys.exit(1)


try:
    with open(sys.argv[1], "rb") as ifile:
        raw = ifile.read() # not the 90s anymore
        with open("bigELF", "wb") as ofile:
            ofile.write(raw[ELF_OFFSET:])
            print("[+] Wrote bigELF")
        with open("header", "wb") as ofile:
            ofile.write(raw[:ELF_OFFSET])
            print("[+] Wrote firmware header")
    with open("bigELF", 'rb') as f:
        elffile = ELFFile(f)
        sz = 0
        for section in elffile.iter_sections():
            sz += section.header['sh_size'] #data_size
        END_OFFSET = ELF_OFFSET + sz
        print(sz,END_OFFSET, END_OFFSET - sz)
    with open("dumped_elf", "wb") as ofile:
        ofile.write(raw[ELF_OFFSET:END_OFFSET])
        os.chmod("dumped_elf", 0o755)
except FileNotFoundError:
    print("File not found - aborting!")
    sys.exit(2)

print("[*] Done")
