package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"unsafe"
)

//#cgo LDFLAGS: -lgcrypt
//#include <stdlib.h>
//#include <dlfcn.h>
//#include "decryptor.h"
import "C"

type section struct {
	offset uint32
	length uint32
}

func newSection(offset uint32, length uint32) *section {
	s := section{offset: offset, length: length}
	return &s
}

func check(e error) {
	if e != nil {
		fmt.Println(e)
		panic(e)
	}
}
func main() {
	flag.Parse()
	fmt.Println("theC64-toolkit")
	args := flag.Args()
	if len(args) < 1 {
		fmt.Println("you must provide a firmware to analyze")
		os.Exit(1)
	}
	if len(args) > 1 {
		fmt.Println("too many arguments provided")
		os.Exit(1)
	}
	fw, err := os.Open(args[0])
	check(err)
	magic := make([]byte, 4)
	_, err = fw.Read(magic)
	check(err)
	mgc := hex.EncodeToString(magic) // TODO: check magic
	correct_mgc := "ac64ac64"
	if mgc != correct_mgc {
		fmt.Println("Invalid magic: " + mgc)
		os.Exit(2)
	}
	fmt.Println("Magic: " + mgc)
	version := make([]byte, 4)
	_, err = fw.Read(version)
	check(err)
	fmt.Print("Version: ")
	fmt.Println(binary.LittleEndian.Uint32(version))
	fw_sha256 := make([]byte, 32)
	_, err = fw.Read(fw_sha256)
	check(err)
	fmt.Print("FW SHA256: ")
	fmt.Println(hex.EncodeToString(fw_sha256))
	installer_offset := make([]byte, 4)
	installer_size := make([]byte, 4)
	_, err = fw.Read(installer_offset)
	check(err)
	_, err = fw.Read(installer_size)
	check(err)
	installer_section := newSection(binary.LittleEndian.Uint32(installer_offset), binary.LittleEndian.Uint32(installer_size))
	old_offset := getFileOffset(fw)
	writeSectionToDisk("installer", *installer_section, fw)
	fw.Seek(old_offset, 0)
	// add installer.enc
	enc_ins_offset := make([]byte, 4)
	enc_ins_size := make([]byte, 4)
	_, err = fw.Read(enc_ins_offset)
	check(err)
	_, err = fw.Read(enc_ins_size)
	enc_installer := newSection(binary.LittleEndian.Uint32(enc_ins_offset), binary.LittleEndian.Uint32(enc_ins_size))
	old_offset = getFileOffset(fw)
	writeSectionToDisk("installer.enc", *enc_installer, fw)
	decryptSection("installer.enc", getEncryptionKey())
	fw.Seek(old_offset, 0)
	// find size of header
	elf_sig, err := hex.DecodeString("7f454c46")
	check(err)
	firmware, err := os.ReadFile(args[0])
	check(err)
	size_of_header := bytes.Index(firmware, elf_sig)
	no_of_ext_sections := (int64(size_of_header) - getFileOffset(fw)) / 8
	fmt.Print("Calculated # of sections: ")
	fmt.Println(no_of_ext_sections)
	offsets := make([]uint32, no_of_ext_sections)
	sizes := make([]uint32, no_of_ext_sections)
	tmp := make([]byte, 4)
	for i := 0; i < int(no_of_ext_sections); i++ {
		_, err := fw.Read(tmp)
		check(err)
		offsets[i] = binary.LittleEndian.Uint32(tmp)
	}
	for i := 0; i < int(no_of_ext_sections); i++ {
		_, err := fw.Read(tmp)
		check(err)
		sizes[i] = binary.LittleEndian.Uint32(tmp)
	}
	ext_sections := make([]*section, no_of_ext_sections)
	for i := 0; i < int(no_of_ext_sections); i++ {
		ext_sections[i] = newSection(offsets[i], sizes[i])
		sectionFilename := "section." + strconv.Itoa(i) + ".enc"
		writeSectionToDisk(sectionFilename, *ext_sections[i], fw)
		decryptSection(sectionFilename, getEncryptionKey())
	}
}

func getFileOffset(fw *os.File) int64 {
	offset, err := fw.Seek(0, io.SeekCurrent)
	check(err)
	return offset

}

func writeSectionToDisk(name string, sect section, fw *os.File) {
	if sect.length == 0 {
		fmt.Println("Skipping " + name)
	}
	ofile, err := os.Create(name)
	check(err)
	fw.Seek(int64(sect.offset), 0)
	tmp := make([]byte, sect.length)
	_, err = fw.Read(tmp)
	check(err)
	_, err = ofile.Write(tmp)
	check(err)
	fmt.Println("Wrote: "+name, sect.offset+sect.length, strconv.FormatInt(int64(sect.offset+sect.length), 16))
}

func getEncryptionKey() []byte {
	// sha256sum(1) of keyfile
	kf256 := "650d9c3dc1860e6be17b3f55be1bf3825af718a43df1c510819ccf87e5ccf214"
	// a little binary ninja goes a long way ...
	recovered_key, err := hex.DecodeString("6631c06689df66f3ab6689e066e8d3ef")
	check(err)
	res := ""
	for i := 0; i < len(recovered_key); i++ {
		digit := byte(kf256[i]) ^ byte(recovered_key[i])
		temp := strconv.FormatInt(int64(digit), 16)
		// poor man's rjust
		if len(temp) == 1 {
			temp = "0" + temp
		}
		res += temp
	}
	foo, err := hex.DecodeString(res)
	check(err)
	return foo
}

func decryptSection(filename string, key []byte) {
	libname := C.CString("./decryptor.so")
	defer C.free(unsafe.Pointer(libname))
	handle := C.dlopen(libname, C.RTLD_LAZY)
	if handle == nil {
		err := fmt.Errorf("error opening decryptor.so")
		check(err)
	}
	defer func() {
		if r := C.dlclose(handle); r != 0 {
			err := fmt.Errorf("Error closing decryptor.so")
			check(err)
		}
	}()

	sym := C.CString("decrypt")
	defer C.free(unsafe.Pointer(sym))
	decrypt := C.dlsym(handle, sym)
	if decrypt == nil {
		err := fmt.Errorf("error resolving decrypt function")
		check(err)
	}
	ret := C.decrypt(C.CString(filename), (*C.char)(unsafe.Pointer(&key[0])))
	defer C.free(unsafe.Pointer(ret))
	ofile, err := os.Create(filename + ".dec.tar.gz")
	check(err)
	// our assumption: files have identical sizes
	fl, err := os.Stat(filename)
	check(err)
	// TODO: pad fl
	err = os.Remove(filename) //TOCTOU
	check(err)
	buffer := C.GoBytes(unsafe.Pointer(ret), C.int(fl.Size()))
	ofile.Write(buffer)
}
