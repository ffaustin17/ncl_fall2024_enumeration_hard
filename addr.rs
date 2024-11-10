use serde::{Deserialize, Serialize};
use std::ops::{Add, Sub};
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(Clone, Copy, Debug)]
pub struct AddrRange(Addr, Addr);

impl AddrRange {
	pub fn new(addr: Addr, len: usize) -> Self {
		let end = usize::from(addr)
			+ len.checked_sub(1).expect("zero-length access");
		Self(addr, Addr::from(end as u32))
	}

	pub const fn start(&self) -> Addr {
		self.0
	}

	pub const fn end(&self) -> Addr {
		self.1
	}

	#[allow(unused)]
	pub fn len(&self) -> usize {
		usize::from(self.1 - self.0) + 1
	}
}

pub type Word = u32;
pub type IWord = i32;

#[derive(
	Clone,
	Copy,
	Debug,
	PartialEq,
	Eq,
	PartialOrd,
	Ord,
	Default,
	Serialize,
	Deserialize,
	FromBytes,
	Immutable,
	IntoBytes,
)]
pub struct Addr(Word);

impl Addr {
	pub const fn new(val: Word) -> Self {
		Self(val)
	}

	pub fn wrapping_add(self, other: Word) -> Self {
		Self(self.0.wrapping_add(other))
	}

	pub fn wrapping_add_signed(self, other: IWord) -> Self {
		Self(self.0.wrapping_add_signed(other))
	}

	pub fn wrapping_sub(&self, other: Word) -> Self {
		Self(self.0.wrapping_sub(other))
	}

	pub fn saturating_sub(&self, other: Word) -> Self {
		Self(self.0.saturating_sub(other))
	}
}

impl Add<Word> for Addr {
	type Output = Self;
	fn add(self, rhs: Word) -> Self::Output {
		Self(self.0.wrapping_add(rhs))
	}
}

impl Add<Addr> for Addr {
	type Output = Self;
	fn add(self, rhs: Addr) -> Self::Output {
		Self(self.0.wrapping_add(rhs.0))
	}
}

impl Sub<Addr> for Addr {
	type Output = Self;
	fn sub(self, rhs: Addr) -> Self::Output {
		Self(self.0.wrapping_sub(rhs.0))
	}
}

impl From<Word> for Addr {
	fn from(val: Word) -> Self {
		Self(val)
	}
}

impl From<Addr> for usize {
	fn from(val: Addr) -> Self {
		val.0 as usize
	}
}

impl From<Addr> for u32 {
	fn from(val: Addr) -> Self {
		val.0
	}
}
