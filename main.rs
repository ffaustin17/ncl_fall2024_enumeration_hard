use std::{
	borrow::Borrow,
	cmp::Ordering,
	fs,
	io::{self, Read, Write},
	thread::sleep,
	time::Duration,
};
use zerocopy::{FromBytes, Immutable, IntoBytes};

mod addr;
use addr::{Addr, AddrRange, IWord, Word};

mod mem;
use mem::Memory;

mod build;
use build::{build_kernel, layout::*, ProgramSegment};

mod instr;
use instr::{Cmp, InsDecoder, Instr, Msr, Reg};

#[derive(Clone, Copy, Debug, Default)]
struct Msrs {
	pmp: Addr,
	pmp_enable: bool,
	sys_handler: Addr,
	smap: bool,
}

impl Msrs {
	fn rdmsr(&self, msr: Msr) -> Word {
		match msr {
			Msr::Pmp => self.pmp.into(),
			Msr::PmpEnable => self.pmp_enable.into(),
			Msr::SysHandler => self.sys_handler.into(),
			Msr::Smap => self.smap.into(),
		}
	}

	fn wrmsr(&mut self, msr: Msr, val: Word) {
		match msr {
			Msr::Pmp => self.pmp = val.into(),
			Msr::PmpEnable => self.pmp_enable = val != 0,
			Msr::SysHandler => self.sys_handler = val.into(),
			Msr::Smap => self.smap = val != 0,
		}
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
enum CpuMode {
	#[default]
	Kern,
	User,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CpuErr {
	InvalidPriv,
	MemFault,
	PmpPrivFault,
	PmpPermFault,
	PmpDisabled,
	SyscallProtection,
	InvalidInstr,
	Io(io::ErrorKind),
}

impl From<io::Error> for CpuErr {
	fn from(value: io::Error) -> Self {
		Self::Io(value.kind())
	}
}

#[derive(Clone, Copy, Debug, Default)]
struct Regs {
	r0: u32,
	r1: u32,
	r2: u32,
	r3: u32,
}

#[derive(Clone, Copy, Debug)]
enum Access {
	Read,
	Write,
	Exec,
}

#[derive(Debug)]
struct Cpu<const N: usize> {
	regs: Regs,
	msrs: Msrs,
	pc: Addr,
	user_pc: Addr,
	cmp: Ordering,
	mode: CpuMode,
	mem: Box<Memory<N>>,
	decoder: InsDecoder,
}

impl<const N: usize> Cpu<N> {
	fn new() -> Self {
		Self {
			regs: Default::default(),
			msrs: Default::default(),
			pc: Default::default(),
			cmp: Ordering::Equal,
			user_pc: Default::default(),
			mode: Default::default(),
			mem: Default::default(),
			decoder: Default::default(),
		}
	}

	fn check_mode(&self, mode: CpuMode) -> Result<(), CpuErr> {
		if self.mode != mode {
			return Err(CpuErr::InvalidPriv);
		}
		Ok(())
	}

	fn check_access(
		&self,
		range: AddrRange,
		acc: Access,
	) -> Result<(), CpuErr> {
		if !self.msrs.pmp_enable {
			return Ok(());
		}

		let pmp = self.mem.get_pmp(self.msrs.pmp)?;
		match self.mode {
			CpuMode::User => {
				pmp.check_access(range, acc, CpuMode::User)?
			}
			CpuMode::Kern => match acc {
				Access::Read | Access::Write if !self.msrs.smap => {
					pmp.check_access(range, acc, CpuMode::User)
						.or_else(|_| {
							pmp.check_access(
								range,
								acc,
								CpuMode::Kern,
							)
						})?
				}
				_ => pmp.check_access(range, acc, CpuMode::Kern)?,
			},
		}

		Ok(())
	}

	fn checked_read<T>(&self, addr: Addr) -> Result<T, CpuErr>
	where
		T: FromBytes,
	{
		let range = AddrRange::new(addr, size_of::<T>());
		self.check_access(range, Access::Read)?;
		self.mem.read_value::<T>(addr)
	}

	fn checked_write<B, T>(
		&mut self,
		addr: Addr,
		val: B,
	) -> Result<(), CpuErr>
	where
		B: Borrow<T>,
		T: IntoBytes + Immutable,
	{
		let range = AddrRange::new(addr, size_of::<T>());
		self.check_access(range, Access::Write)?;
		self.mem.write_value(addr, val)?;
		Ok(())
	}

	fn fetch_instruction(&self, addr: Addr) -> Result<Instr, CpuErr> {
		let raw = self.mem.read_value(addr)?;
		self.decoder.decode(raw)
	}

	fn checked_exec_single(&mut self) -> Result<bool, CpuErr> {
		let range = AddrRange::new(self.pc, Instr::LEN);
		self.check_access(range, Access::Exec)?;
		let ins = self.fetch_instruction(self.pc)?;

		self.pc = self.pc.wrapping_add(Instr::LEN as u32);
		self.exec_single(ins)
	}

	fn store_reg(&mut self, reg: Reg, val: Word) {
		match reg {
			Reg::R0 => self.regs.r0 = val,
			Reg::R1 => self.regs.r1 = val,
			Reg::R2 => self.regs.r2 = val,
			Reg::R3 => self.regs.r3 = val,
		}
	}

	const fn load_reg(&self, reg: Reg) -> Word {
		match reg {
			Reg::R0 => self.regs.r0,
			Reg::R1 => self.regs.r1,
			Reg::R2 => self.regs.r2,
			Reg::R3 => self.regs.r3,
		}
	}

	fn check_syscall_protection(
		&self,
		addr: Addr,
	) -> Result<(), CpuErr> {
		let range = AddrRange::new(addr, Instr::LEN);
		let pmp = self.mem.get_pmp(self.msrs.pmp)?;
		match pmp.check_access(range, Access::Write, CpuMode::User) {
			Ok(()) => Err(CpuErr::SyscallProtection),
			Err(CpuErr::PmpPermFault) => Ok(()),
			_ => unreachable!(),
		}
	}

	fn exec_single(&mut self, ins: Instr) -> Result<bool, CpuErr> {
		match ins {
			Instr::Nop => (),
			Instr::Pcall => {
				self.check_mode(CpuMode::User)?;
				let prev = self.pc.wrapping_sub(Instr::LEN as Word);
				self.check_syscall_protection(prev)?;

				self.mode = CpuMode::Kern;
				self.user_pc = self.pc;
				self.pc = self.msrs.sys_handler;
			}
			Instr::Pret => {
				self.check_mode(CpuMode::Kern)?;
				if !self.msrs.pmp_enable {
					return Err(CpuErr::PmpDisabled);
				}
				self.mode = CpuMode::User;
				self.pc = self.user_pc;
			}
			Instr::Rdmsr(arg) => {
				let val = self.msrs.rdmsr(arg.msr);
				self.store_reg(arg.reg, val);
			}
			Instr::Wrmsr(arg) => {
				self.check_mode(CpuMode::Kern)?;
				let val = self.load_reg(arg.reg);
				self.msrs.wrmsr(arg.msr, val);
			}
			Instr::ReadImm4(arg) => {
				let val = self.checked_read::<u32>(arg.addr)?;
				self.store_reg(arg.reg, val as Word);
			}
			Instr::ReadImm2(arg) => {
				let val = self.checked_read::<u16>(arg.addr)?;
				self.store_reg(arg.reg, val as Word);
			}
			Instr::ReadImm1(arg) => {
				let val = self.checked_read::<u8>(arg.addr)?;
				self.store_reg(arg.reg, val as Word);
			}
			Instr::ReadPtr4(arg) => {
				let ptr = Addr::new(self.load_reg(arg.rb));
				let val = self.checked_read::<u32>(ptr)?;
				self.store_reg(arg.ra, val);
			}
			Instr::ReadPtr2(arg) => {
				let ptr = Addr::new(self.load_reg(arg.rb));
				let val = self.checked_read::<u16>(ptr)?;
				self.store_reg(arg.ra, val as Word);
			}
			Instr::ReadPtr1(arg) => {
				let ptr = Addr::new(self.load_reg(arg.rb));
				let val = self.checked_read::<u8>(ptr)?;
				self.store_reg(arg.ra, val as Word);
			}
			Instr::WriteImm4(arg) => {
				let val = self.load_reg(arg.reg);
				self.checked_write(arg.addr, val)?;
			}
			Instr::WriteImm2(arg) => {
				let val = self.load_reg(arg.reg) as u16;
				self.checked_write(arg.addr, val)?;
			}
			Instr::WriteImm1(arg) => {
				let val = self.load_reg(arg.reg) as u8;
				self.checked_write(arg.addr, val)?;
			}
			Instr::WritePtr4(arg) => {
				let val = self.load_reg(arg.rb);
				let addr = Addr::new(self.load_reg(arg.ra));
				self.checked_write(addr, val)?;
			}
			Instr::WritePtr2(arg) => {
				let val = self.load_reg(arg.rb) as u16;
				let addr = Addr::new(self.load_reg(arg.ra));
				self.checked_write(addr, val)?;
			}
			Instr::WritePtr1(arg) => {
				let val = self.load_reg(arg.rb) as u8;
				let addr = Addr::new(self.load_reg(arg.ra));
				self.checked_write(addr, val)?;
			}
			Instr::Add(arg) => {
				let rb = self.load_reg(arg.rb);
				let rc = self.load_reg(arg.rc);
				self.store_reg(arg.ra, rb.wrapping_add(rc));
			}
			Instr::Addi(arg) => {
				let rb = self.load_reg(arg.rb);
				let rc = self.load_reg(arg.rc) as IWord;
				self.store_reg(arg.ra, rb.wrapping_add_signed(rc));
			}
			Instr::Mul(arg) => {
				let rb = self.load_reg(arg.rb);
				let rc = self.load_reg(arg.rc);
				self.store_reg(arg.ra, rb.wrapping_mul(rc));
			}
			Instr::Mov(arg) => self.store_reg(arg.reg, arg.val),
			Instr::Cmp(arg) => {
				let ra = self.load_reg(arg.ra);
				let rb = self.load_reg(arg.rb);
				self.cmp = ra.cmp(&rb);
			}
			Instr::Jmp(reg) => {
				self.pc = self.load_reg(reg).into();
			}
			Instr::JmpImm(val) => {
				self.pc = val.into();
			}
			Instr::JmpCmp(arg) => {
				if self.check_cmp(arg.cmp) {
					self.pc = self.load_reg(arg.reg).into();
				}
			}
			Instr::JmpRel(reg) => {
				self.jmp_rel(reg);
			}
			Instr::JmpRelCmp(arg) => {
				if self.check_cmp(arg.cmp) {
					self.jmp_rel(arg.reg);
				}
			}
			Instr::Out(reg) => {
				self.check_mode(CpuMode::Kern)?;
				let val = self.load_reg(reg);
				match char::from_u32(val) {
					Some(c) => print!("{c}"),
					None => print!("\\x{val:x}"),
				}
				std::io::stdout().flush().unwrap();
			}
			Instr::Sleep(reg) => {
				self.check_mode(CpuMode::Kern)?;
				let val = self.load_reg(reg);
				sleep(Duration::from_millis(val as u64));
			}
			Instr::Halt => {
				self.check_mode(CpuMode::Kern)?;
				return Ok(true);
			}
		}
		Ok(false)
	}

	fn check_cmp(&self, cmp: Cmp) -> bool {
		match cmp {
			Cmp::Eq => self.cmp.is_eq(),
			Cmp::Neq => !self.cmp.is_eq(),
			Cmp::Ge => self.cmp.is_ge(),
			Cmp::Gt => self.cmp.is_gt(),
			Cmp::Le => self.cmp.is_le(),
			Cmp::Lt => self.cmp.is_lt(),
		}
	}

	fn jmp_rel(&mut self, reg: Reg) {
		let cnt = self.load_reg(reg).wrapping_add_signed(-1) as IWord;
		let off = cnt.wrapping_mul(Instr::LEN as IWord);
		self.pc = self.pc.wrapping_add_signed(off);
	}

	fn run(&mut self) {
		loop {
			match self.checked_exec_single() {
				Err(e) => {
					self.panic(e);
					break;
				}
				Ok(true) => break,
				_ => (),
			}
		}
	}

	fn panic(&self, e: CpuErr) {
		eprintln!("-----------------------");
		eprintln!("ERROR: {e:?}");
		eprintln!("-----------------------");
		eprintln!("PC  = {:08x}", u32::from(self.pc));
		eprintln!("CMP = {:?}", self.cmp);
		eprintln!("{:#x?}", self.regs);
		eprintln!("-----------------------");
	}

	fn load_kernel(
		&mut self,
		segs: &[ProgramSegment],
	) -> Result<(), CpuErr> {
		if let Some(seg) = segs.first() {
			self.pc = seg.addr;
		}
		for seg in segs {
			self.mem
				.get_raw_bytes_mut(seg.addr, seg.code.len())?
				.copy_from_slice(&seg.code);
		}
		Ok(())
	}

	fn load_user(
		&mut self,
		app: ProgramSegment,
	) -> Result<(), CpuErr> {
		self.mem
			.get_raw_bytes_mut(app.addr, app.code.len())?
			.copy_from_slice(&app.code);
		self.user_pc = app.addr;
		self.regs.r0 = app.addr.into();
		self.regs.r1 = app.code.len() as u32;
		Ok(())
	}
}

fn usage() -> ! {
	let arg0 = std::env::args().next().unwrap_or_default();
	eprintln!("{arg0} <program>");
	std::process::exit(1);
}

fn main() -> Result<(), CpuErr> {
	let Some(file) = std::env::args().nth(1) else {
		usage();
	};
	let mut prog = Vec::new();
	fs::File::open(file)?.read_to_end(&mut prog)?;
	assert!(prog.len() <= USER_SIZE as usize);
	let user = ProgramSegment::raw_data(USER_BASE, &prog);
	let kern = build_kernel();

	let mut cpu = Cpu::<ADDR_MAX>::new();
	cpu.load_kernel(&kern)?;
	cpu.load_user(user)?;
	cpu.run();

	Ok(())
}
