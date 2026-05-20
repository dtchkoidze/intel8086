package main

import "core:bytes"
import "core:fmt"
import "core:log"
import "core:os"
import "core:path/filepath"
import "core:strings"

find_executable :: proc(name: string) -> (string, bool) {
	path_env, ok := os.lookup_env_alloc("PATH", context.allocator)
	if !ok do return "", false

	dirs := strings.split(path_env, ":")
	defer delete(dirs)

	for dir in dirs {
		full, err := filepath.join({dir, name}, context.allocator)
		if err != nil do return "", false
		if os.exists(full) {
			stat, err := os.stat(full, context.allocator)
			defer os.file_info_delete(stat, context.allocator)
			if err != nil do return "", false
			is_exec := os.Permissions_Execute_All & stat.mode != {}
			if is_exec {
				return full, true
			}
		}
		delete(full)
	}
	return "", false
}

ModRM :: bit_field u8 {
	rm:  u8 | 3,
	reg: u8 | 3,
	mod: u8 | 2,
}

Instruction :: bit_field u8 {
	w:  u8 | 1,
	d:  u8 | 1,
	op: u8 | 6,
}

reg_name :: proc(reg: u8, w: u8) -> string {
	w1 := [8]string{"ax", "cx", "dx", "bx", "sp", "bp", "si", "di"}
	w0 := [8]string{"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"}
	return w1[reg] if w == 1 else w0[reg]
}

rm_name :: proc(rm: u8, mod: Mod, displcmnt: i16, w: u8) -> string {
	switch mod {
	case .RegMode:
		return reg_name(rm, w)
	case .MemMode, .MemMode8Bit, .MemMode16Bit:
		base := [8]string{"bx+si", "bx+di", "bp+si", "bp+di", "si", "di", "bp", "bx"}
		if mod == .MemMode && rm == 0b110 {
			return fmt.aprintf("[%d]", displcmnt)
		}
		if displcmnt == 0 {
			return fmt.aprintf("[%s]", base[rm])
		}
		return fmt.aprintf("[%s+%d]", base[rm], displcmnt)
	}
	return "EHM DUNNO"
}

compile :: proc(filename: string) -> ([]byte, bool) {
	data, err := os.read_entire_file(filename, context.allocator)
	if err != nil {
		log.errorf("failed to read file %v", err)
		return []byte{}, false
	}
	defer delete(data)

	nasmexe, oknasm := find_executable("nasm")
	if !oknasm {
		log.errorf("failed to find nasm executable on machine")
		return []byte{}, false
	}

	binf := strings.join([]string{"/tmp/", filename, ".bin"}, "", context.allocator)

	command := []string{nasmexe, "-f", "bin", filename, "-o", binf}
	process, perr := os.process_start({command = command, stdout = os.stdout, stderr = os.stderr})
	if perr != nil {
		log.error(perr)
		return []byte{}, false
	}
	s, werr := os.process_wait(process)
	if werr != nil {
		kerr := os.process_kill(process)
		if kerr != nil {
			return []byte{}, false
		}
		return []byte{}, false
	}

	bdata, berr := os.read_entire_file(binf, context.allocator)
	if berr != nil {
		log.errorf("failed to read binary file: %v", err)
		return []byte{}, false
	}

	return bdata, true
}


Mod :: enum u8 {
	MemMode      = 0b00, //Memory Mode, no displacement follows*
	MemMode8Bit  = 0b01, //Memory Mode, 8-bit displacement follows
	MemMode16Bit = 0b10, //Memory Mode, 16-bit displacement followS
	RegMode      = 0b11, //Register Mode (nodisplacement)
}

main :: proc() {
	logger := log.create_console_logger()
	context.logger = logger
	if len(os.args) <= 1 {
		log.errorf("usage: %s <filename>", os.args[0])
		return
	}

	filename := os.args[1]
	log.infof("decoding: %s", filename)

	bdata, ok := compile(filename)
	if !ok {
		log.errorf("failed to compile asm")
		return
	}
	defer delete(bdata)

	log.infof("read %d bytes", len(bdata))
	log.infof("%b", bdata)

	asmStr: string = "bits 16"
	i := 0
	for i < len(bdata) {
		instr := transmute(Instruction)bdata[i]
		if instr.op == 0b100010 { 	//here we do have modrm
			// reg/mem mov
			modrm := transmute(ModRM)bdata[i + 1]
			i += 2
			MOD := Mod(modrm.mod)
			displacement: i16 = 0

			switch MOD {
			case .MemMode:
				if modrm.rm == 0b110 {
					displacement = (^i16)(&bdata[i])^
					i += 2
				}
			case .RegMode:
			case .MemMode8Bit:
				displacement = i16(i8(bdata[i]))
				i += 1
			case .MemMode16Bit:
				displacement = (^i16)(&bdata[i])^
				i += 2
			}

			op1 := reg_name(modrm.reg, instr.w)
			op2 := rm_name(modrm.rm, MOD, displacement, instr.w)
			if instr.d == 0 do op1, op2 = op2, op1

			line := fmt.aprintf("mov %s, %s", op1, op2)
			asmStr = strings.join([]string{asmStr, line}, "\n", context.allocator)

		} else if bdata[i] >> 4 == 0b1011 { 	//no modrm second octet is just data
			// immediate to register
			w := (bdata[i] >> 3) & 1
			reg := bdata[i] & 0b111
			i += 1
			imm: i16
			if w == 1 {
				imm = (^i16)(&bdata[i])^
				i += 2
			} else {
				imm = i16(i8(bdata[i]))
				i += 1
			}
			line := fmt.aprintf("mov %s, %d", reg_name(reg, w), imm)
			asmStr = strings.join([]string{asmStr, line}, "\n", context.allocator)
		} else {
			log.errorf("unknown opcode: %08b", bdata[i])
			break
		}
	}
	// results
	log.info("_____________________")
	log.infof("final asm: \n\n%s\n", asmStr)
	log.infof("testing binary...")

	tmpAsmFname := "tmp_asm.asm"
	werr := os.write_entire_file_from_string(tmpAsmFname, asmStr, os.Permissions_All, true)
	if werr != nil {
		log.errorf("failed to write temporary asm: %v", werr)
		return
	}
	defer os.remove(tmpAsmFname)

	rdata, cok := compile(tmpAsmFname)
	if !ok {
		log.errorf("failed to compile tmp asm")
		return
	}
	defer delete(rdata)

	if bytes.compare(bdata, rdata) != 0 {
		log.errorf("binaries mismatch")
		return
	}
	log.info("_______success_______")
}
