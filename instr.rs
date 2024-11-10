use core::fmt;

use crate::{
	addr::{Addr, Word},
	CpuErr,
};
use bincode::{
	config::{
		AllowTrailing, Bounded, FixintEncoding, WithOtherIntEncoding,
		WithOtherLimit, WithOtherTrailing,
	},
	DefaultOptions, Options,
};
use serde::{Deserialize, Serialize};

#[repr(u8)]
#[derive(
	Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq,
)]
pub enum Msr {
	Pmp,
	PmpEnable,
	SysHandler,
	Smap,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum Reg {
	R0,
	R1,
	R2,
	R3,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct Rdmsr {
	pub msr: Msr,
	pub reg: Reg,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct Wrmsr {
	pub msr: Msr,
	pub reg: Reg,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct RegArith {
	pub ra: Reg,
	pub rb: Reg,
	pub rc: Reg,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct RegIo {
	pub reg: Reg,
	pub addr: Addr,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct RegMov {
	pub reg: Reg,
	pub val: Word,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct RegCmp {
	pub ra: Reg,
	pub rb: Reg,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum Cmp {
	Eq,
	Neq,
	Ge,
	Gt,
	Le,
	Lt,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct JmpCmp {
	pub cmp: Cmp,
	pub reg: Reg,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct RegPtr {
	pub ra: Reg,
	pub rb: Reg,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum Instr {
	Nop,
	Pcall,
	Pret,
	Rdmsr(Rdmsr),
	Wrmsr(Wrmsr),
	ReadImm4(RegIo),
	ReadImm2(RegIo),
	ReadImm1(RegIo),
	ReadPtr4(RegPtr),
	ReadPtr2(RegPtr),
	ReadPtr1(RegPtr),
	WriteImm4(RegIo),
	WriteImm2(RegIo),
	WriteImm1(RegIo),
	WritePtr4(RegPtr),
	WritePtr2(RegPtr),
	WritePtr1(RegPtr),
	Add(RegArith),
	Addi(RegArith),
	Mul(RegArith),
	Mov(RegMov),
	Cmp(RegCmp),
	Jmp(Reg),
	JmpImm(Word),
	JmpCmp(JmpCmp),
	JmpRel(Reg),
	JmpRelCmp(JmpCmp),
	Out(Reg),
	Sleep(Reg),
	Halt,
}

impl Instr {
	pub const fn mov(reg: Reg, val: Word) -> Self {
		Self::Mov(RegMov { reg, val })
	}
	#[allow(dead_code)]
	pub const fn rdmsr(msr: Msr, reg: Reg) -> Self {
		Self::Rdmsr(Rdmsr { msr, reg })
	}

	pub const fn wrmsr(msr: Msr, reg: Reg) -> Self {
		Self::Wrmsr(Wrmsr { msr, reg })
	}

	pub const fn add(ra: Reg, rb: Reg, rc: Reg) -> Self {
		Self::Add(RegArith { ra, rb, rc })
	}

	#[allow(dead_code)]
	pub const fn read_imm4(reg: Reg, addr: Addr) -> Self {
		Self::ReadImm4(RegIo { reg, addr })
	}

	#[allow(dead_code)]
	pub const fn read_ptr4(ra: Reg, rb: Reg) -> Self {
		Self::ReadPtr4(RegPtr { ra, rb })
	}

	#[allow(dead_code)]
	pub const fn write_ptr4(ra: Reg, rb: Reg) -> Self {
		Self::WritePtr4(RegPtr { ra, rb })
	}
}

impl Instr {
	pub const LEN: usize = 16;
}

type InternalDecoder = WithOtherTrailing<
	WithOtherLimit<
		WithOtherIntEncoding<DefaultOptions, FixintEncoding>,
		Bounded,
	>,
	AllowTrailing,
>;

pub struct InsDecoder(InternalDecoder);

impl InsDecoder {
	pub fn new() -> Self {
		Self(
			DefaultOptions::new()
				.with_fixint_encoding()
				.with_limit(Instr::LEN as u64)
				.allow_trailing_bytes(),
		)
	}

	pub fn decode(
		&self,
		bytes: [u8; Instr::LEN],
	) -> Result<Instr, CpuErr> {
		self.0.deserialize(&bytes).map_err(|_| CpuErr::InvalidInstr)
	}

	pub fn encode(&self, val: &Instr) -> Result<Vec<u8>, CpuErr> {
		self.0.serialize(val).map_err(|_| CpuErr::InvalidInstr)
	}
}

impl fmt::Debug for InsDecoder {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("InsDecoder").finish()
	}
}

impl Default for InsDecoder {
	fn default() -> Self {
		Self::new()
	}
}
