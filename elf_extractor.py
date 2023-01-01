#!/usr/bin/env python3
import re
import os
import sys
import glob
from elftools.elf.elffile import ELFFile


ELF_MGC= re.compile(rb"\x7f\x45\x4c\x46")

if len(sys.argv) != 2:
    print(sys.argv[0] + " firmware")
    sys.exit(1)


def find_suitable_filename(filename):
    if not os.path.exists(filename):
        return filename
    elif not os.path.exists(filename + "." + str(1)):
        return filename + "." + str(1)
    else:
        fnames = glob.glob(filename+".*")
        postfix = int(fnames[-1].split(".")[-1])
        postfix += 1
        return find_suitable_filename(filename + "." + str(postfix))

def strip_firmware_hdr(filename, offset):
    with open(find_suitable_filename(filename), "wb") as ofile:
        ofile.write(raw[ELF_OFFSET:])

def write_firmware_hdr(filename, offset):
    with open(find_suitable_filename(filename), "wb") as ofile:
        ofile.write(raw[:offset])

def calculate_elf_sz(filename):
    fname = glob.glob(filename+"*")[-1] # assumes at least one match
    with open(fname, 'rb') as f:
        print(fname)
        elffile = ELFFile(f)
        phentsz = elffile['e_phentsize']
        phnum = elffile['e_phnum']
        shentsz = elffile['e_shentsize']
        shnum = elffile['e_shnum']
        ehsz = elffile['e_ehsize']
        sz = ehsz + phnum * phentsz
        for section in elffile.iter_sections():
            sz += section.header['sh_size']
    return sz

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
        strip_firmware_hdr("bigELF", ELF_OFFSET)
        print("[+] Wrote bigELF")
        write_firmware_hdr("header", ELF_OFFSET)
        print("[+] Wrote firmware header")
        elf_size = calculate_elf_sz("bigELF")
        END_OFFSET = ELF_OFFSET + elf_size
        print(elf_size)
        dumped = find_suitable_filename("dumped_elf")
    with open(dumped, "wb") as ofile:
        ofile.write(raw[ELF_OFFSET:END_OFFSET])
    os.chmod(dumped, 0o755)
except FileNotFoundError:
    print("Firmware not found - aborting!")
    sys.exit(2)

print("[*] Done")
