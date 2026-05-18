package main

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

main :: proc() {
	logger := log.create_console_logger()
	context.logger = logger

	if len(os.args) <= 1 {
		log.errorf("usage: %s <filename>", os.args[0])
		return
	}

	filename := os.args[1]
	log.infof("decoding: %s", filename)
	data, err := os.read_entire_file(filename, context.allocator)
	if err != nil {
		log.errorf("failed to read file %v", err)
		return
	}

	nasmexe, oknasm := find_executable("nasm")
	if !oknasm {
		log.errorf("failed to find nasm executable on machine")
		return
	}

	binf := strings.join([]string{"/tmp/", filename, ".bin"}, "", context.allocator)

	command := []string{nasmexe, "-f", "bin", filename, "-o", binf}
	process, perr := os.process_start({command = command, stdout = os.stdout, stderr = os.stderr})
	if perr != nil {
		log.error(perr)
		return
	}
	s, werr := os.process_wait(process)
	if werr != nil {
		kerr := os.process_kill(process)
		if kerr != nil {
			log.fatal(err)
		}
		return
	}

	bdata, berr := os.read_entire_file(binf, context.allocator)
	if berr != nil {
		log.errorf("failed to read binary file: %v", err)
		return
	}

	log.infof("read %d bytes", len(bdata))
	log.infof("%b", bdata)

	asmStr: string
	for i := 0; i < len(bdata); i += 2 {
		instructionString: string
		op1: string
		op2: string

		instr := transmute(Instruction)bdata[i]
		modrm := transmute(ModRM)bdata[i+1]

		if instr.op == 0b100010 {
			instructionString = "mov"
			log.info("dw: ", instr.d, instr.w)
			log.info("modrm", modrm)
			regissrc := instr.d == 0
			log.infof("register is source == %v", regissrc)
			log.infof("reg:%03b, rm: %03b", modrm.reg, modrm.rm)

			op1 = reg_name(modrm.reg, instr.w)
			op2 = reg_name(modrm.rm, instr.w)
			if regissrc {
				op1, op2 = op2, op1
			}
		}

		line := strings.join([]string{instructionString, op1, op2}, " ", context.allocator)
		asmStr = strings.join([]string{asmStr, line}, "\n", context.allocator)
	}

	// results
	log.info("_____________________________________")
	log.infof("final asm: \n %s", asmStr)
}
