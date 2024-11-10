use std::{borrow::Borrow, ops::Deref};

use crate::{
	addr::{AddrRange, Word},
	Access, Addr, CpuErr, CpuMode,
};
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct RawPmp {
	pub kern: Addr,
	pub user: Addr,
}

const _: () = assert!(size_of::<RawPmp>() == 8);

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct RawPmpTable(pub [RawPmpEntry; 32]);

const _: () = assert!(size_of::<RawPmpTable>() == 256);

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct RawPmpEntry {
	pub start: Word,
	pub len: Word,
}

const _: () = assert!(size_of::<RawPmpEntry>() == 8);

#[derive(Clone, Copy, Debug)]
pub struct PmpTable([PmpEntry; 32]);

impl Deref for PmpTable {
	type Target = [PmpEntry; 32];
	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl From<RawPmpTable> for PmpTable {
	fn from(value: RawPmpTable) -> Self {
		Self(value.0.map(Into::into))
	}
}

bitflags::bitflags! {
	#[derive(Clone, Copy, Debug)]
	pub struct PmpPerms: u8 {
		const READ  = 0b001;
		const WRITE = 0b010;
		const EXEC  = 0b100;
	}
}

#[derive(Clone, Copy, Debug)]
pub struct PmpEntry {
	pub start: Addr,
	pub len: Word,
	pub perms: PmpPerms,
}

impl PmpEntry {
	fn end(&self) -> Addr {
		self.start + self.len
	}

	fn enabled(&self) -> bool {
		self.len != 0
	}

	fn contains(&self, r: AddrRange) -> bool {
		self.start <= r.start() && r.end() < self.end()
	}
}

impl From<RawPmpEntry> for PmpEntry {
	fn from(value: RawPmpEntry) -> Self {
		let start = value.start >> 12;
		let perms = value.start & 0xff;
		Self {
			start: start.into(),
			len: value.len,
			perms: PmpPerms::from_bits_truncate(perms as u8),
		}
	}
}

#[derive(Clone, Copy, Debug)]
pub struct Pmp {
	pub kern: PmpTable,
	pub user: PmpTable,
}

impl Pmp {
	pub fn check_access(
		&self,
		range: AddrRange,
		acc: Access,
		mode: CpuMode,
	) -> Result<(), CpuErr> {
		let table = match mode {
			CpuMode::User => &self.user,
			CpuMode::Kern => &self.kern,
		};
		let region = table
			.iter()
			.filter(|r| r.enabled())
			.find(|r| r.contains(range))
			.ok_or(CpuErr::PmpPrivFault)?;

		let ok = match acc {
			Access::Read => region.perms.contains(PmpPerms::READ),
			Access::Write => region.perms.contains(PmpPerms::WRITE),
			Access::Exec => {
				region.perms.contains(PmpPerms::EXEC | PmpPerms::READ)
			}
		};

		if !ok {
			return Err(CpuErr::PmpPermFault);
		}

		Ok(())
	}
}

#[derive(Debug)]
pub struct Memory<const N: usize>([u8; N]);

impl<const N: usize> Memory<N> {
	pub const fn new() -> Self {
		Self([0; N])
	}

	pub fn read_raw_bytes(
		&self,
		addr: Addr,
		len: usize,
	) -> Result<&[u8], CpuErr> {
		let start = addr.into();
		let end = start + len;
		self.0.get(start..end).ok_or(CpuErr::MemFault)
	}

	pub fn get_raw_bytes_mut(
		&mut self,
		addr: Addr,
		len: usize,
	) -> Result<&mut [u8], CpuErr> {
		let start = addr.into();
		let end = start + len;
		self.0.get_mut(start..end).ok_or(CpuErr::MemFault)
	}

	pub fn read_value<T: FromBytes>(
		&self,
		addr: Addr,
	) -> Result<T, CpuErr> {
		let bytes = self.read_raw_bytes(addr, size_of::<T>())?;
		T::read_from_bytes(bytes).map_err(|_| CpuErr::MemFault)
	}

	pub fn write_value<B, T>(
		&mut self,
		addr: Addr,
		val: B,
	) -> Result<(), CpuErr>
	where
		B: Borrow<T>,
		T: IntoBytes + Immutable,
	{
		let bytes = self.get_raw_bytes_mut(addr, size_of::<T>())?;
		bytes.copy_from_slice(val.borrow().as_bytes());
		Ok(())
	}

	fn get_pmp_table(&self, addr: Addr) -> Result<PmpTable, CpuErr> {
		self.read_value::<RawPmpTable>(addr).map(Into::into)
	}

	pub fn get_pmp(&self, addr: Addr) -> Result<Pmp, CpuErr> {
		let raw = self.read_value::<RawPmp>(addr)?;
		let kern = self.get_pmp_table(raw.kern)?;
		let user = self.get_pmp_table(raw.user)?;

		Ok(Pmp { kern, user })
	}
}

impl<const N: usize> Default for Memory<N> {
	fn default() -> Self {
		Self::new()
	}
}
