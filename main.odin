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

Fmt :: enum u8 {
	None,
	ModRM,
	Imm8,
	Imm16,
	RegImm,
	RegOnly,
	Rel8,
	Rel16,
	AccMem,
	ImmGroup,
}

Op_Info :: struct {
	kind: Op_Kind,
	fmt:  Fmt,
}

op_info :: proc(opcode: u8) -> (Op_Info, bool) {
	if opcode >> 2 == 0b100010 {return Op_Info{.Mov_RM_To_From_Reg, .ModRM}, true}
	if opcode >> 1 == 0b1100011 {return Op_Info{.Mov_Imm_To_RM, .ModRM}, true}
	if opcode >> 4 == 0b1011 {return Op_Info{.Mov_Imm_To_Reg, .RegImm}, true}
	if opcode >> 1 == 0b1010000 {return Op_Info{.Mov_Mem_To_Acc, .AccMem}, true}
	if opcode >> 1 == 0b1010001 {return Op_Info{.Mov_Acc_To_Mem, .AccMem}, true}
	if opcode == 0b10001110 {return Op_Info{.Mov_RM_To_Seg, .ModRM}, true}
	if opcode == 0b10001100 {return Op_Info{.Mov_Seg_To_RM, .ModRM}, true}

	if opcode >> 2 == 0b000000 {return Op_Info{.Add_RM_To_RM, .ModRM}, true}
	if opcode >> 2 == 0b100000 {return Op_Info{.Add_Imm_To_RM, .ModRM}, true}
	if opcode >> 1 == 0b0000010 {return Op_Info{.Add_Imm_To_Acc, .Imm16}, true}



	return {}, false
}

mnemonic_from_kind :: proc(k: Op_Kind) -> string {
	kint := int(k)
	if kint >= 0 && kint < 7 {
		return "mov"
	}

	if kint >= 7 && kint < 10 {
		return "add"
	}

	return "dunno"
}

read_displacement :: proc(bdata: []byte, i: ^int, modrm: ModRM) -> i16 {

	mod := Mod(modrm.mod)

	switch mod {
	case .MemMode:
		// Except when R/M = 110, then 16-bit displacement follows
		if modrm.rm == 0b110 {
			disp := (^i16)(&bdata[i^])^
			i^ += 2
			return disp
		}

		return 0

	case .MemMode8Bit:
		disp := i16(i8(bdata[i^]))
		i^ += 1
		return disp

	case .MemMode16Bit:
		disp := (^i16)(&bdata[i^])^
		i^ += 2
		return disp

	case .RegMode:
		return 0
	}

	return 0
}

read_imm :: proc(bdata: []byte, i: ^int, w: u8) -> i16 {
	if w == 1 {
		v := (^i16)(&bdata[i^])^; i^ += 2; return v
	}
	v := i16(i8(bdata[i^])); i^ += 1; return v
}

decode_ops :: proc(bdata: []byte, i: ^int, opcode: u8, info: Op_Info) -> string {
	switch info.fmt {
	case .None:
		return ""
	case .RegOnly:
		reg := opcode & 0b111
		return decode_reg(reg, 1) // always 16-bit
	case .RegImm:
		w := (opcode >> 3) & 1
		reg := opcode & 0b111
		imm := read_imm(bdata, i, w)
		return fmt.aprintf("%s, %d", decode_reg(reg, w), imm)
	case .Rel8:
		rel := i16(i8(bdata[i^])); i^ += 1
		return fmt.aprintf("%+d", rel) // or compute abs addr if you track IP
	case .Rel16:
		rel := (^i16)(&bdata[i^])^; i^ += 2
		return fmt.aprintf("%+d", rel)
	case .AccMem:
		w := opcode_w(opcode)
		addr := (^u16)(&bdata[i^])^; i^ += 2
		acc := "ax" if w == 1 else "al"
		if info.kind == .Mov_Mem_To_Acc {
			return fmt.aprintf("%s, [%d]", acc, addr)
		}
		return fmt.aprintf("[%d], %s", addr, acc)
	case .ModRM:
		modrm := transmute(ModRM)bdata[i^]
		i^ += 1 // acc for modrm
		displacement := read_displacement(bdata, i, modrm)
		w := opcode_w(opcode)
		rmop := decode_rm(modrm.rm, Mod(modrm.mod), displacement, w)

		if info.kind == .Mov_Imm_To_RM {
			imm := read_imm(bdata, i, w)
			size := "byte" if w == 0 else "word"
			if Mod(modrm.mod) != .RegMode {
				return fmt.aprintf("%s %s, %d", size, rmop, imm)
			}
			return fmt.aprintf("%s, %d", rmop, imm)
		}


		regop := decode_reg(modrm.reg, w)

		dst := regop
		src := rmop

		if opcode_d(opcode) == 0 {
			dst = rmop
			src = regop
		}

		ops := strings.join([]string{dst, src}, ", ", context.allocator)
		return ops
	case .ImmGroup:
	case .Imm16:

	case .Imm8:
		imm := bdata[i^]; i^ += 1
		return fmt.aprintf("%d", imm)
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
		log.infof("opcode: %08b", opcode)
		i += 1
		op_info, ok := op_info(opcode)
		log.infof("opinfo: %v", op_info)

		if !ok {
			log.errorf("unknown operation: %08b", opcode)
			return
		}
		mnemonic := mnemonic_from_kind(op_info.kind)
		ops := decode_ops(bdata, &i, opcode, op_info)
		line := ops == "" ? mnemonic : fmt.aprintf("%s %s", mnemonic, ops)
		log.infof("LINE: %s", line)
		asmStr = strings.join({asmStr, line}, "\n", context.allocator)
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
	if !cok {
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
