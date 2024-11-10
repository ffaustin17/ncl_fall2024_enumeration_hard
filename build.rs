use layout::*;
use zerocopy::{FromZeros, Immutable, IntoBytes};

use crate::{
	addr::{Addr, Word},
	instr::{InsDecoder, Instr, Msr, Reg},
	mem::{PmpPerms, RawPmp, RawPmpEntry, RawPmpTable},
};

pub mod layout {
	use super::*;

	pub const USER_BASE: Word = 0x0;
	pub const USER_SIZE: Word = 0x4000;

	pub const PMP_BASE: Word = USER_BASE + USER_SIZE;

	pub const PMP0_BASE: Word =
		PMP_BASE + size_of::<RawPmp>() as Word;

	pub const PMP1_BASE: Word =
		PMP0_BASE + size_of::<RawPmpTable>() as Word;
	const _: () = assert!(
		PMP1_BASE + (size_of::<RawPmpTable>() as Word) < KERN_BASE
	);

	pub const KERN_BASE: Word = 0x5000;

	pub const SYS_BASE: Word = 0x7000;
	pub const SYS_SIZE: Word = 0x100;

	pub const SYS0_BASE: Word = SYS_BASE + SYS_SIZE;

	pub const SYS1_BASE: Word = SYS0_BASE + SYS_SIZE;
	const _: () = assert!(SYS1_BASE + SYS_SIZE <= FLAG_BASE);

	pub const FLAG_BASE: Word = 0x9000;

	pub const ADDR_MAX: usize = 0x10000;
}

#[derive(Debug, Clone)]
pub struct ProgramSegment {
	pub addr: Addr,
	pub code: Vec<u8>,
}

impl ProgramSegment {
	pub fn code<A: Into<Addr>>(addr: A, ins: &[Instr]) -> Self {
		let addr = addr.into();
		let mut code = Vec::new();
		let enc = InsDecoder::new();
		for ins in ins.iter() {
			let mut bytes = enc.encode(ins).unwrap();
			bytes.resize(Instr::LEN, 0);
			code.extend_from_slice(&bytes);
		}
		Self { addr, code }
	}

	pub fn data<A, D>(addr: A, data: D) -> Self
	where
		A: Into<Addr>,
		D: IntoBytes + Immutable,
	{
		Self {
			addr: addr.into(),
			code: data.as_bytes().to_vec(),
		}
	}

	pub fn raw_data<A, B>(addr: A, data: B) -> Self
	where
		A: Into<Addr>,
		B: AsRef<[u8]>,
	{
		Self {
			addr: addr.into(),
			code: data.as_ref().to_vec(),
		}
	}
}

fn build_kernel_pmp<A: Into<Addr>>(addr: A) -> ProgramSegment {
	let mut table = RawPmpTable::new_zeroed();
	let perms = PmpPerms::READ | PmpPerms::EXEC;
	table.0[0] = RawPmpEntry {
		start: KERN_BASE << 12 | perms.bits() as Word,
		len: ADDR_MAX as Word - KERN_BASE,
	};

	ProgramSegment::data(addr, table)
}

fn build_user_pmp<A: Into<Addr>>(addr: A) -> ProgramSegment {
	let mut user = RawPmpTable::new_zeroed();
	let perms = PmpPerms::READ | PmpPerms::WRITE | PmpPerms::EXEC;
	user.0[0] = RawPmpEntry {
		start: USER_BASE << 12 | perms.bits() as Word,
		len: KERN_BASE - USER_BASE,
	};
	ProgramSegment::data(addr, user)
}

fn build_pmp() -> Vec<ProgramSegment> {
	let mut pmp = Vec::new();

	let base = RawPmp {
		kern: Addr::new(PMP0_BASE),
		user: Addr::new(PMP1_BASE),
	};
	pmp.push(ProgramSegment::data(PMP_BASE, base));
	pmp.push(build_kernel_pmp(PMP0_BASE));
	pmp.push(build_user_pmp(PMP1_BASE));

	pmp
}

fn build_bootloader<A: Into<Addr>>(addr: A) -> ProgramSegment {
	fn print_msg(ins: &mut Vec<Instr>, msg: &str) {
		for c in msg.chars() {
			ins.push(Instr::mov(Reg::R2, c as Word));
			ins.push(Instr::Out(Reg::R2));
		}
	}

	fn write_msr(ins: &mut Vec<Instr>, msr: Msr, val: Word) {
		ins.push(Instr::mov(Reg::R0, val));
		ins.push(Instr::wrmsr(msr, Reg::R0))
	}

	let mut bootloader = Vec::new();
	print_msg(&mut bootloader, "[..] Booting MicroYoshi kernel\n");

	write_msr(&mut bootloader, Msr::SysHandler, SYS_BASE);

	write_msr(&mut bootloader, Msr::Pmp, PMP_BASE);
	write_msr(&mut bootloader, Msr::PmpEnable, 1);
	write_msr(&mut bootloader, Msr::Smap, 1);

	print_msg(&mut bootloader, "[OK] Booted MicroYoshi kernel\n");
	print_msg(&mut bootloader, "[..] Launching userspace\n");
	bootloader.push(Instr::Pret);

	ProgramSegment::code(addr, &bootloader)
}

fn build_flag<A: Into<Addr>>(addr: A) -> ProgramSegment {
	let flag = String::from(std::env!("CTF_FLAG"));
	ProgramSegment::raw_data(addr, flag.as_bytes())
}

pub fn build_kernel() -> Vec<ProgramSegment> {
	let bootloader = build_bootloader(KERN_BASE);
	assert!((bootloader.code.len() as u32) < (KERN_BASE - USER_BASE));

	const SYS: &[Instr] = &[
		Instr::mov(Reg::R3, 1),
		Instr::add(Reg::R0, Reg::R0, Reg::R3),
		Instr::JmpRel(Reg::R0),
		Instr::JmpImm(SYS0_BASE),
		Instr::JmpImm(SYS1_BASE),
	];
	const { assert!(SYS.len() * Instr::LEN <= SYS_SIZE as usize) };

	const SYS0: &[Instr] = &[Instr::Out(Reg::R1), Instr::Pret];
	const { assert!(SYS0.len() * Instr::LEN <= SYS_SIZE as usize) };

	const SYS1: &[Instr] = &[Instr::Sleep(Reg::R1), Instr::Pret];
	const { assert!(SYS1.len() * Instr::LEN <= SYS_SIZE as usize) };

	let mut kernel = vec![
		bootloader,
		ProgramSegment::code(SYS_BASE, SYS),
		ProgramSegment::code(SYS0_BASE, SYS0),
		ProgramSegment::code(SYS1_BASE, SYS1),
		build_flag(FLAG_BASE),
	];
	kernel.extend(build_pmp());
	kernel
}
