use crate::pic::Thunkable;
use std::mem;

use super::Register;

#[repr(C, packed)]
struct CallAbs {
  // call [rip+8]
  opcode0: u8,
  opcode1: u8,
  dummy0: u32,
  // jmp +10
  dummy1: u8,
  dummy2: u8,
  // destination
  address: usize,
}

pub fn call_abs(destination: usize) -> Box<dyn Thunkable> {
  let code = CallAbs {
    opcode0: 0xFF,
    opcode1: 0x15,
    dummy0: 0x0_0000_0002,
    dummy1: 0xEB,
    dummy2: 0x08,
    address: destination,
  };

  let slice: [u8; 16] = unsafe { mem::transmute(code) };
  Box::new(slice.to_vec())
}

#[repr(C, packed)]
struct JumpAbs {
  // jmp +6
  opcode0: u8,
  opcode1: u8,
  dummy0: u32,
  // destination
  address: usize,
}

pub fn jmp_abs(destination: usize) -> Box<dyn Thunkable> {
  let code = JumpAbs {
    opcode0: 0xFF,
    opcode1: 0x25,
    dummy0: 0x0_0000_0000,
    address: destination,
  };

  let slice: [u8; 14] = unsafe { mem::transmute(code) };
  Box::new(slice.to_vec())
}

#[repr(C, packed)]
struct JccAbs {
  // jxx + 16
  opcode: u8,
  dummy0: u8,
  dummy1: u8,
  dummy2: u8,
  dummy3: u32,
  // destination
  address: usize,
}

pub fn jcc_abs(destination: usize, condition: u8) -> Box<dyn Thunkable> {
  let code = JccAbs {
    // Invert the condition in x64 mode to simplify the conditional jump logic
    opcode: 0x71 ^ condition,
    dummy0: 0x0E,
    dummy1: 0xFF,
    dummy2: 0x25,
    dummy3: 0x0000_0000,
    address: destination,
  };

  let slice: [u8; 16] = unsafe { mem::transmute(code) };
  Box::new(slice.to_vec())
}

pub fn mov_reg_extended(src: Register, dst: Register) -> Box<dyn Thunkable> {
  let rex = 0x48;
  let opcode = 0x89;
  let src = src as u8;
  let dst = dst as u8;

  let m = 0b11 << 6;
  let src = src << 3;
  Box::new(vec![rex, opcode, m | src | dst])
}

pub fn and_reg_i32_extended(register: Register, imm: i32) -> Box<dyn Thunkable> {
  let rex = 0x48;
  let opcode = 0x81;
  let register = register as u8;
  let m = 0b11 << 6;
  let reg = 0b100 << 3;
  let mod_r_m = m | reg | register;
  let imm = imm.to_le_bytes();

  let mut bytes = vec![rex, opcode, mod_r_m];
  bytes.extend_from_slice(&imm);
  Box::new(bytes)
}

pub fn pushfq() -> Box<dyn Thunkable> {
  Box::new(vec![0x9C_u8])
}

pub fn popfq() -> Box<dyn Thunkable> {
  Box::new(vec![0x9D_u8])
}

pub fn sub_reg_i32_extended(register: Register, imm: i32) -> Box<dyn Thunkable> {
  let rex = 0x48;
  let opcode = 0x81;
  let register = register as u8;
  let m = 0b11 << 6;
  let reg = 0b101 << 3;
  let mod_r_m = m | reg | register;
  let imm = imm.to_le_bytes();

  let mut bytes = vec![rex, opcode, mod_r_m];
  bytes.extend_from_slice(&imm);
  Box::new(bytes)
}

pub fn add_reg_i32_extended(register: Register, imm: i32) -> Box<dyn Thunkable> {
  let rex = 0x48;
  let opcode = 0x81;
  let register = register as u8;
  let m = 0b11 << 6;
  let reg = 0b000 << 3;
  let mod_r_m = m | reg | register;
  let imm = imm.to_le_bytes();

  let mut bytes = vec![rex, opcode, mod_r_m];
  bytes.extend_from_slice(&imm);
  Box::new(bytes)
}

pub fn push_all_regs() -> Box<dyn Thunkable> {
  use iced_x86::code_asm::*;
  let mut builder = CodeAssembler::new(64).unwrap();
  builder.push(rsp).unwrap();
  builder.push(rbp).unwrap();
  builder.push(rax).unwrap();
  builder.push(rbx).unwrap();
  builder.push(rcx).unwrap();
  builder.push(rdx).unwrap();
  builder.push(rsi).unwrap();
  builder.push(rdi).unwrap();
  builder.push(r8).unwrap();
  builder.push(r9).unwrap();
  builder.push(r10).unwrap();
  builder.push(r11).unwrap();
  builder.push(r12).unwrap();
  builder.push(r13).unwrap();
  builder.push(r14).unwrap();
  builder.push(r15).unwrap();
  Box::new(builder.assemble(0x00).unwrap())
}

pub fn pop_all_regs() -> Box<dyn Thunkable> {
  use iced_x86::code_asm::*;
  let mut builder = CodeAssembler::new(64).unwrap();
  builder.pop(r15).unwrap();
  builder.pop(r14).unwrap();
  builder.pop(r13).unwrap();
  builder.pop(r12).unwrap();
  builder.pop(r11).unwrap();
  builder.pop(r10).unwrap();
  builder.pop(r9).unwrap();
  builder.pop(r8).unwrap();
  builder.pop(rdi).unwrap();
  builder.pop(rsi).unwrap();
  builder.pop(rdx).unwrap();
  builder.pop(rcx).unwrap();
  builder.pop(rbx).unwrap();
  builder.pop(rax).unwrap();
  builder.pop(rbp).unwrap();
  builder.pop(rsp).unwrap();
  Box::new(builder.assemble(0x00).unwrap())
}
