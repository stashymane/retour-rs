use disasm::*;
use std::{mem, slice};

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, OpKind};

use crate::{Error, Result, pic, util::BITNESS};

use super::{
  thunk::{self, Register},
  trampoline::disasm,
};

/// A mid-function hook.
///
/// `hook` is not directly used as this isn't a detour, there needs to be
/// preparation before calling `hook` since jumping to hook directly can be a
/// disaster
pub struct Hook {
  emitter: pic::CodeEmitter,
}

impl Hook {
  /// Constructs a new mid-function hook for an address.
  pub unsafe fn new(target: *const (), hook: *const (), original_first: bool) -> Result<Self> {
    Builder::new(target, hook, original_first).build()
  }

  pub fn emitter(&self) -> &pic::CodeEmitter {
    &self.emitter
  }
}

struct Builder {
  target: *const (),
  hook: *const (),
  original_first: bool,
}

impl Builder {
  /// Creates a mid-function hook.
  ///
  /// # Safety
  ///
  /// target..target+15 must be valid to read as u8 slice or behavior may be
  /// undefined
  fn new(target: *const (), hook: *const (), original_first: bool) -> Self {
    Builder {
      target,
      hook,
      original_first,
    }
  }

  unsafe fn build(mut self) -> Result<Hook> {
    // get target instruction
    let target: *const u8 = self.target.cast();
    let slice = unsafe { slice::from_raw_parts(std::hint::black_box(target), 15) };
    let mut decoder = Decoder::with_ip(BITNESS, slice, self.target as u64, DecoderOptions::NONE);
    let inst = decoder.decode();
    if inst.is_invalid() {
      return Err(Error::InvalidCode);
    }
    if inst.len() < 5 {
      return Err(Error::NoPatchArea);
    }
    let inst_bytes = &slice[..inst.len()];
    let inst_flow = inst.flow_control();

    let mut emitter = pic::CodeEmitter::new();

    if self.original_first {
      if matches!(
        inst_flow,
        FlowControl::UnconditionalBranch
          | FlowControl::IndirectBranch
          | FlowControl::ConditionalBranch
          | FlowControl::Return
          // TODO: unsure if instructions below can cause problems, so better error than going wrong
          | FlowControl::Interrupt
          | FlowControl::XbeginXabortXend
          | FlowControl::Exception
      ) {
        return Err(Error::UnsupportedInstruction);
      }

      let inst = self.process_instruction(&inst, inst_bytes)?;
      emitter.add_thunk(inst);
    }

    // save flags and registers, then align sp
    #[cfg(target_arch = "x86_64")]
    {
      emitter.add_thunk(thunk::x64::pushfq());
      emitter.add_thunk(thunk::x64::push_all_regs());
      emitter.add_thunk(thunk::x64::mov_reg_extended(Register::sp, Register::bp));
      emitter.add_thunk(thunk::x64::and_reg_i32_extended(Register::sp, -16));
      // Windows x64 ABI requires 32 bytes of shadow space before any call
      #[cfg(target_os = "windows")]
      emitter.add_thunk(thunk::x64::sub_reg_i32_extended(Register::sp, 32));
    }
    #[cfg(target_arch = "x86")]
    {
      emitter.add_thunk(thunk::x86::pushfd());
      emitter.add_thunk(thunk::x86::push_all_regs());
      emitter.add_thunk(thunk::x86::mov_reg(Register::sp, Register::bp));
      emitter.add_thunk(thunk::x86::and_reg_i32(Register::sp, -16));
    }

    // actually call hook
    emitter.add_thunk(thunk::call(self.hook as usize));

    // restore sp, registers, then flags
    #[cfg(target_arch = "x86_64")]
    {
      // Remove shadow space reserved for Windows x64 ABI
      #[cfg(target_os = "windows")]
      emitter.add_thunk(thunk::x64::add_reg_i32_extended(Register::sp, 32));
      emitter.add_thunk(thunk::x64::mov_reg_extended(Register::bp, Register::sp));
      emitter.add_thunk(thunk::x64::pop_all_regs());
      emitter.add_thunk(thunk::x64::popfq());
    }
    #[cfg(target_arch = "x86")]
    {
      emitter.add_thunk(thunk::x86::mov_reg(Register::bp, Register::sp));
      emitter.add_thunk(thunk::x86::pop_all_regs());
      emitter.add_thunk(thunk::x86::popfd());
    }

    if !self.original_first {
      let inst = self.process_instruction(&inst, inst_bytes)?;
      emitter.add_thunk(inst);
    }

    emitter.add_thunk(thunk::jmp(self.target as usize + inst.len()));

    Ok(Hook { emitter })
  }

  /// Returns an instruction after analysing and potentially modifies it.
  unsafe fn process_instruction(
    &mut self,
    instruction: &Instruction,
    instruction_bytes: &[u8],
  ) -> Result<Box<dyn pic::Thunkable>> {
    if let Some(target) = instruction.rip_operand_target() {
      return self.handle_rip_relative_instruction(instruction, instruction_bytes, target as usize);
    } else if let Some(target) = instruction.relative_branch_target() {
      return self.handle_relative_branch(instruction, instruction_bytes, target as usize);
    }

    // The instruction does not use any position-dependant operands,
    // therefore the bytes can be copied directly from source.
    Ok(Box::new(instruction_bytes.to_vec()))
  }

  /// Processes relative branches (e.g `call`, `loop`, `jne`).
  unsafe fn handle_relative_branch(
    &mut self,
    instruction: &Instruction,
    instruction_bytes: &[u8],
    destination_address_abs: usize,
  ) -> Result<Box<dyn pic::Thunkable>> {
    if instruction.is_call() {
      // Calls are not an issue since they return to the original address
      return Ok(thunk::call(destination_address_abs));
    }

    if instruction.is_loop() {
      // Loops (e.g 'loopnz', 'jecxz') to the outside are not supported
      Err(Error::UnsupportedInstruction)
    } else if instruction.is_unconditional_jump() {
      Ok(thunk::jmp(destination_address_abs))
    } else {
      // Conditional jumps (Jcc)
      // To extract the condition, the primary opcode is required. Short
      // jumps are only one byte, but long jccs are prefixed with 0x0F.
      let primary_opcode = instruction_bytes
        .iter()
        .find(|op| **op != 0x0F)
        .expect("retrieving conditional jump primary op code");

      // Extract the condition (i.e 0x74 is [jz rel8] ⟶ 0x74 & 0x0F == 4)
      let condition = primary_opcode & 0x0F;
      Ok(thunk::jcc(destination_address_abs, condition))
    }
  }

  /// Adjusts the offsets for RIP relative operands. They are only available
  /// in x64 processes. The operands offsets needs to be adjusted for their
  /// new position. An example would be:
  ///
  /// ```asm
  /// mov eax, [rip+0x10]   ; the displacement before relocation
  /// mov eax, [rip+0x4892] ; theoretical adjustment after relocation
  /// ```
  unsafe fn handle_rip_relative_instruction(
    &mut self,
    instruction: &Instruction,
    instruction_bytes: &[u8],
    target: usize,
  ) -> Result<Box<dyn pic::Thunkable>> {
    let displacement = target
      .wrapping_sub(instruction.ip() as usize)
      .wrapping_sub(instruction.len()) as isize;

    let instruction_address = instruction.ip() as isize;
    let instruction_bytes = instruction_bytes.to_vec();
    let immediate_size = instruction
      .op_kinds()
      .find_map(|kind| match kind {
        OpKind::Immediate8 => Some(1),
        OpKind::Immediate8_2nd => Some(1),
        OpKind::Immediate16 => Some(2),
        OpKind::Immediate32 => Some(4),
        OpKind::Immediate64 => Some(8),
        OpKind::Immediate8to16 => Some(1),
        OpKind::Immediate8to32 => Some(1),
        OpKind::Immediate8to64 => Some(1),
        OpKind::Immediate32to64 => Some(4),
        _ => None,
      })
      .unwrap_or(0);

    Ok(Box::new(pic::UnsafeThunk::new(
      move |offset| {
        let mut bytes = instruction_bytes.clone();

        // Calculate the new relative displacement for the operand. The
        // instruction is relative so the offset (i.e where the trampoline is
        // allocated), must be within a range of +/- 2GB.
        let adjusted_displacement = instruction_address
          .wrapping_sub(offset as isize)
          .wrapping_add(displacement);
        assert!(crate::arch::is_within_range(adjusted_displacement));

        // The displacement value is placed at (instruction - disp32 - imm)
        let index = instruction_bytes.len() - mem::size_of::<u32>() - immediate_size;

        // Write the adjusted displacement offset to the operand
        let as_bytes: [u8; 4] = (adjusted_displacement as u32).to_ne_bytes();
        bytes[index..index + as_bytes.len()].copy_from_slice(&as_bytes);
        bytes
      },
      instruction.len(),
    )))
  }
}
