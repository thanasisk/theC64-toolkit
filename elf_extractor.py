#!/usr/bin/env python3
import re
import os
import sys
from elftools.elf.elffile import ELFFile


ELF_MGC= re.compile(rb"\x7f\x45\x4c\x46")

if len(sys.argv) != 2:
    print(sys.argv[0] + " firmware")
    sys.exit(1)

try:
    with open(sys.argv[1], "rb") as ifile:
        signature = ifile.read(4)
        if signature != b"\xac\x64\xac\x64":
            print("[-] Invalid signature detected!")
            print(signature)
            sys.exit(-4)
        ifile.seek(0)
        raw = ifile.read() # not the 90s anymore
        offset = ELF_MGC.search(raw)
        if offset is not None:
            ELF_OFFSET = offset.start()
        else:
            print("[-] Unable to locate ELF within blob - quitting")
            sys.exit(3)
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
    with open("dumped_elf", "wb") as ofile:
        ofile.write(raw[ELF_OFFSET:END_OFFSET])
        os.chmod("dumped_elf", 0o755)
except FileNotFoundError:
    print("Firmware not found - aborting!")
    sys.exit(2)

print("[*] Done")
