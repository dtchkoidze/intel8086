package main

import "core:bytes"
import "core:fmt"
import "core:log"
import "core:os"
import "core:strings"

ModRM :: bit_field u8 {
	rm:  u8 | 3,
	reg: u8 | 3,
	mod: u8 | 2,
}

opcode_w :: proc(opcode: byte) -> u8 {
	return opcode & 1
}

opcode_d :: proc(opcode: byte) -> u8 {
	return (opcode >> 1) & 1
}

opcode_s :: proc(opcode: byte) -> u8 {
	return (opcode >> 1) & 1
}

opcode_op6 :: proc(opcode: byte) -> u8 {
	return opcode >> 2
}

decode_reg :: proc(reg: u8, w: u8) -> string {
	w1 := [8]string{"ax", "cx", "dx", "bx", "sp", "bp", "si", "di"}
	w0 := [8]string{"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"}
	return w1[reg] if w == 1 else w0[reg]
}

decode_rm :: proc(rm: u8, mod: Mod, displcmnt: i16, w: u8) -> string {
	switch mod {
	case .RegMode:
		return decode_reg(rm, w)
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

// first two bits of MODRM
// MOD | REG | RM
Mod :: enum u8 {
	MemMode      = 0b00, //Memory Mode, no displacement follows*
	MemMode8Bit  = 0b01, //Memory Mode, 8-bit displacement follows
	MemMode16Bit = 0b10, //Memory Mode, 16-bit displacement followS
	RegMode      = 0b11, //Register Mode (nodisplacement)
}

Op_Kind :: enum u8 {
	Mov_RM_To_From_Reg,
	Mov_Imm_To_RM,
	Mov_Imm_To_Reg,
	Mov_Mem_To_Acc,
	Mov_Acc_To_Mem,
	Mov_RM_To_Seg,
	Mov_Seg_To_RM,
	Add_RM_To_RM,
	Add_Imm_To_RM,
	Add_Imm_To_Acc,
}

Op_Info :: struct {
	kind:      Op_Kind,
	has_modrm: bool,
}

op_info :: proc(opcode: u8) -> (Op_Info, bool) {
	if opcode >> 2 == 0b100010 {
		return Op_Info{.Mov_RM_To_From_Reg, true}, true
	}

	if opcode >> 1 == 0b1100011 {
		return Op_Info{.Mov_Imm_To_RM, true}, true
	}

	if opcode >> 4 == 0b1011 {
		return Op_Info{.Mov_Imm_To_Reg, false}, true
	}

	if opcode >> 1 == 0b1010000 {
		return Op_Info{.Mov_Mem_To_Acc, false}, true
	}

	if opcode >> 1 == 0b1010001 {
		return Op_Info{.Mov_Acc_To_Mem, false}, true
	}

	if opcode == 0b10001110 {
		return Op_Info{.Mov_RM_To_Seg, true}, true
	}

	if opcode == 0b10001100 {
		return Op_Info{.Mov_Seg_To_RM, true}, true
	}

	if opcode >> 2 == 0b000000 {
		return Op_Info{.Add_RM_To_RM, true}, true
	}

	return {}, false
}

mnemonic_from_kind :: proc(k: Op_Kind) -> string {
	kint := int(k)
	if kint >= 0 && kint <= 7 {
		return "mov"
	}

	if kint > 7 && kint < 10 {
		return "add"
	}

	return "dunno"
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
		opcode := bdata[i] //ok first bbyte, can have extra w,d,s,op6 in it
		op_info, ok := op_info(opcode)
		if !ok {
			log.errorf("unknown operation: %08b", opcode)
			return
		}
		mnemonic := mnemonic_from_kind(op_info.kind)
		log.infof("doing %s: %v", mnemonic, op_info)
		i += 1 //account just for opcode

		rmop: string //reg/mod operand
		regop: string //reg operand
		displacement: i16

		if op_info.has_modrm {
			modrm := transmute(ModRM)bdata[i]
			i += 1 // acc for modrm
			log.infof("modrm: %v", modrm)
			rmop := decode_rm(modrm.rm, Mod(modrm.mod), displacement, opcode_w(opcode))
			regop := decode_reg(modrm.reg, opcode_w(opcode))

			dst := regop
			src := rmop

			if opcode_d(opcode) == 0 {
				dst = rmop
				src = regop
			}

			ops := strings.join([]string{rmop, regop}, ", ", context.allocator)
			line := strings.join([]string{mnemonic, ops}, " ", context.allocator)
			log.info(line)
			asmStr = strings.join([]string{asmStr, line}, "\n", context.allocator)
		} else {

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
