mod parse;

use std::fmt;
use std::ops::Range;

use derive_more::*;
use derive_try_from_primitive::TryFromPrimitive;
use enumflags2::*;

#[derive(thiserror::Error, Debug)]
pub enum ReadRelaError {
    #[error("{0}")]
    DynamicEntryNotFound(#[from] GetDynamicEntryError),
    #[error("Rela segment not found")]
    RelaSegmentNotFound,
    #[error("Parsing error: {0}")]
    ParsingError(String),
}

#[derive(thiserror::Error, Debug)]
pub enum GetStringError {
    #[error("StrTab dynamic entry not found")]
    StrTabNotFound,
    #[error("StrTab segment not found")]
    StrTabSegmentNotFound,
    #[error("String not found")]
    StringNotFound,
}

// #[derive(Error, Debug)]
#[derive(thiserror::Error, Debug)]
pub enum ReadSymsError {
    #[error("{0:?}")]
    DynamicEntryNotFound(#[from] GetDynamicEntryError),

    #[error("SymTab section not found")]
    SymTabSectionNotFound,

    #[error("SymTab segment not found")]
    SymTabSegmentNotFound,

    #[error("Parsing error: {0}")]
    ParsingError(String),
}

#[derive(thiserror::Error, Debug)]
pub enum GetDynamicEntryError {
    #[error("Dynamic entry {0:?} not found")]
    NotFound(DynamicTag),
}

// "Add" and "Sub" are in `derive_more`
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Add, Sub)]
pub struct Addr(pub u64);

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

// This will come in handy when serializing
impl Into<u64> for Addr {
    fn into(self) -> u64 {
        self.0
    }
}

// This will come in handy when indexing / sub-slicing slices
impl Into<usize> for Addr {
    fn into(self) -> usize {
        self.0 as usize
    }
}

// This will come in handy when parsing
impl From<u64> for Addr {
    fn from(x: u64) -> Self {
        Self(x)
    }
}

impl Addr {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        use nom::{combinator::map, number::complete::le_u64};
        map(le_u64, From::from)(i)
    }

    pub unsafe fn as_ptr<T>(&self) -> *const T {
        std::mem::transmute(self.0 as usize)
    }

    pub unsafe fn as_mut_ptr<T>(&self) -> *mut T {
        std::mem::transmute(self.0 as usize)
    }

    pub unsafe fn as_slice<T>(&self, len: usize) -> &[T] {
        std::slice::from_raw_parts(self.as_ptr(), len)
    }

    pub unsafe fn as_mut_slice<T>(&self, len: usize) -> &mut [T] {
        std::slice::from_raw_parts_mut(self.as_mut_ptr(), len)
    }

    pub unsafe fn write(&self, src: &[u8]) {
        std::ptr::copy_nonoverlapping(src.as_ptr(), self.as_mut_ptr(), src.len());
    }

    pub unsafe fn set<T>(&self, src: T) {
        *self.as_mut_ptr() = src;
    }
}

pub struct HexDump<'a>(&'a [u8]);

impl<'a> fmt::Debug for HexDump<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &x in self.0.iter().take(20) {
            write!(f, "{:02x}", x)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum Type {
    None = 0x0,
    Rel = 0x1,
    Exec = 0x2,
    Dyn = 0x3,
    Core = 0x4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum Machine {
    X86 = 0x03,
    X86_64 = 0x3e,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u32)]
pub enum SegmentType {
    Null = 0x0,
    Load = 0x1,
    Dynamic = 0x2,
    Interp = 0x3,
    Note = 0x4,
    ShLib = 0x5,
    PHdr = 0x6,
    TLS = 0x7,
    LoOS = 0x6000_0000,
    HiOS = 0x6FFF_FFFF,
    LoProc = 0x7000_0000,
    HiProc = 0x7FFF_FFFF,
    GnuEhFrame = 0x6474_E550,
    GnuStack = 0x6474_E551,
    GnuRelRo = 0x6474_E552,
    GnuProperty = 0x6474_E553,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, BitFlags)]
#[repr(u32)]
pub enum SegmentFlag {
    Execute = 0x1,
    Write = 0x2,
    Read = 0x4,
}

impl_parse_for_enum!(SegmentType, le_u32);
impl_parse_for_enum!(Type, le_u16);
impl_parse_for_enum!(Machine, le_u16);
impl_parse_for_enumflags!(SegmentFlag, le_u32);

#[derive(Debug, TryFromPrimitive, PartialEq, Eq, Clone, Copy)]
#[repr(u64)]
pub enum DynamicTag {
    Null = 0,
    Needed = 1,
    PltRelSz = 2,
    PltGot = 3,
    Hash = 4,
    StrTab = 5,
    SymTab = 6,
    Rela = 7,
    RelaSz = 8,
    RelaEnt = 9,
    StrSz = 10,
    SymEnt = 11,
    Init = 12,
    Fini = 13,
    SoName = 14,
    RPath = 15,
    Symbolic = 16,
    Rel = 17,
    RelSz = 18,
    RelEnt = 19,
    PltRel = 20,
    Debug = 21,
    TextRel = 22,
    JmpRel = 23,
    BindNow = 24,
    InitArray = 25,
    FiniArray = 26,
    InitArraySz = 27,
    FiniArraySz = 28,

    Flags = 30,
    GnuHash = 0x6ffffef5,
    VerSym = 0x6ffffff0,
    RelaCount = 0x6ffffff9,
    Flags1 = 0x6ffffffb,
    VerDef = 0x6ffffffc,
    VerDefNum = 0x6ffffffd,
    VerNeed = 0x6ffffffe,
    VerNeedNum = 0x6fffffff,
}

impl_parse_for_enum!(DynamicTag, le_u64);

#[derive(Debug)]
pub struct DynamicEntry {
    pub tag: DynamicTag,
    pub addr: Addr,
}

impl DynamicEntry {
    fn parse(i: parse::Input) -> parse::Result<Self> {
        use nom::sequence::tuple;
        let (i, (tag, addr)) = tuple((DynamicTag::parse, Addr::parse))(i)?;
        Ok((i, Self { tag, addr }))
    }
}

#[derive(Debug)]
pub enum SegmentContents {
    Dynamic(Vec<DynamicEntry>),
    Unknown,
}

#[derive(Debug, TryFromPrimitive, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum KnownRelType {
    _64 = 1,
    Copy = 5,
    GlobDat = 6,
    JumpSlot = 7,
    Relative = 8,
}

impl_parse_for_enum!(KnownRelType, le_u32);

#[derive(Debug, TryFromPrimitive, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RelType {
    _64 = 1,
    Copy = 5,
    GlobDat = 6,
    JumpSlot = 7,
    Relative = 8,
}

impl_parse_for_enum!(RelType, le_u32);

#[derive(Debug)]
pub struct Rela {
    pub offset: Addr,
    pub r#type: RelType,
    pub sym: u32,
    pub addend: Addr,
}

impl Rela {
    const SIZE: usize = 24;

    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        use nom::{combinator::map, number::complete::le_u32, sequence::tuple};
        map(
            tuple((Addr::parse, RelType::parse, le_u32, Addr::parse)),
            |(offset, r#type, sym, addend)| Rela {
                offset,
                r#type,
                sym,
                addend,
            },
        )(i)
    }
}

#[derive(Debug, TryFromPrimitive, Clone, Copy)]
#[repr(u8)]
pub enum SymBind {
    Local = 0,
    Global = 1,
    Weak = 2,
}

impl_parse_for_bitenum!(SymBind, 4_usize);

#[derive(Debug, TryFromPrimitive, Clone, Copy)]
#[repr(u8)]
pub enum SymType {
    None = 0,
    Object = 1,
    Func = 2,
    Section = 3,
}

impl_parse_for_bitenum!(SymType, 4_usize);

#[derive(Clone, Copy)]
pub struct SectionIndex(pub u16);

impl SectionIndex {
    pub fn is_undef(&self) -> bool {
        self.0 == 0
    }

    pub fn is_special(&self) -> bool {
        self.0 >= 0xff00
    }

    pub fn get(&self) -> Option<usize> {
        if self.is_undef() || self.is_special() {
            None
        } else {
            Some(self.0 as usize)
        }
    }
}

impl fmt::Debug for SectionIndex {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_special() {
            write!(f, "Special({:04x})", self.0)
        } else if self.is_undef() {
            write!(f, "Undef")
        } else {
            write!(f, "{}", self.0)
        }
    }
}

#[derive(Debug, Clone)]
pub struct Sym {
    pub bind: SymBind,
    pub r#type: SymType,
    pub name: Addr,
    pub shndx: SectionIndex,
    pub value: Addr,
    pub size: u64,
}

impl Sym {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        use nom::{
            bits::bits,
            combinator::map,
            number::complete::{le_u16, le_u32, le_u64, le_u8},
            sequence::tuple,
        };

        let (i, (name, (bind, r#type), _reserved, shndx, value, size)) = tuple((
            map(le_u32, |x| Addr(x as u64)),
            bits(tuple((SymBind::parse, SymType::parse))),
            le_u8,
            map(le_u16, SectionIndex),
            Addr::parse,
            le_u64,
        ))(i)?;
        let res = Self {
            name,
            bind,
            r#type,
            shndx,
            value,
            size,
        };
        Ok((i, res))
    }
}

#[derive(Debug)]
pub struct SectionHeader {
    pub name: Addr,
    pub r#type: u32,
    pub flags: u64,
    pub addr: Addr,
    pub off: Addr,
    pub size: Addr,
    pub link: u32,
    pub info: u32,
    pub addralign: Addr,
    pub entsize: Addr,
}

impl SectionHeader {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        use nom::{
            combinator::map,
            number::complete::{le_u32, le_u64},
            sequence::tuple,
        };
        let (i, (name, r#type, flags, addr, off, size, link, info, addralign, entsize)) =
            tuple((
                map(le_u32, |x| Addr(x as u64)),
                le_u32,
                le_u64,
                Addr::parse,
                Addr::parse,
                Addr::parse,
                le_u32,
                le_u32,
                Addr::parse,
                Addr::parse,
            ))(i)?;
        let res = Self {
            name,
            r#type,
            flags,
            addr,
            off,
            size,
            link,
            info,
            addralign,
            entsize,
        };
        Ok((i, res))
    }
}

pub struct ProgramHeader {
    pub r#type: SegmentType,
    pub flags: BitFlags<SegmentFlag>,
    pub offset: Addr,
    pub vaddr: Addr,
    pub paddr: Addr,
    pub filesz: Addr,
    pub memsz: Addr,
    pub align: Addr,
    pub data: Vec<u8>,
    pub contents: SegmentContents,
}

impl ProgramHeader {
    fn parse<'a>(full_input: parse::Input<'a>, i: parse::Input<'a>) -> parse::Result<'a, Self> {
        use nom::sequence::tuple;
        let (i, (r#type, flags)) = tuple((SegmentType::parse, SegmentFlag::parse))(i)?;

        let ap = Addr::parse;
        let (i, (offset, vaddr, paddr, filesz, memsz, align)) = tuple((ap, ap, ap, ap, ap, ap))(i)?;

        use nom::{
            combinator::{map, verify},
            multi::many_till,
        };
        let slice = &full_input[offset.into()..][..filesz.into()];
        let (_, contents) = match r#type {
            SegmentType::Dynamic => map(
                many_till(
                    DynamicEntry::parse,
                    verify(DynamicEntry::parse, |e| e.tag == DynamicTag::Null),
                ),
                |(entries, _last)| SegmentContents::Dynamic(entries),
            )(slice)?,
            _ => (slice, SegmentContents::Unknown),
        };

        let res = Self {
            r#type,
            flags,
            offset,
            vaddr,
            paddr,
            filesz,
            memsz,
            align,
            data: slice.to_vec(),
            contents,
        };
        Ok((i, res))
    }
    /**
     * File range where the segment is stored
     */
    pub fn file_range(&self) -> Range<Addr> {
        self.offset..self.offset + self.filesz
    }

    /**
     * Memory range where the segment is mapped
     */
    pub fn mem_range(&self) -> Range<Addr> {
        self.vaddr..self.vaddr + self.memsz
    }
}

impl fmt::Debug for ProgramHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "file {:?} | mem {:?} | align {:?} | {} {:?}",
            self.file_range(),
            self.mem_range(),
            self.align,
            // the default Debug formatter for `enumflags2` is a bit
            // on the verbose side, let's print something like `RWX` instead
            &[
                (SegmentFlag::Read, "R"),
                (SegmentFlag::Write, "W"),
                (SegmentFlag::Execute, "X")
            ]
            .iter()
            .map(|&(flag, letter)| {
                if self.flags.contains(flag) {
                    letter
                } else {
                    "."
                }
            })
            .collect::<Vec<_>>()
            .join(""),
            self.r#type,
        )
    }
}

#[derive(Debug)]
pub struct File {
    pub r#type: Type,
    pub machine: Machine,
    pub entry_point: Addr,
    pub program_headers: Vec<ProgramHeader>,
    pub section_headers: Vec<SectionHeader>,
}

impl File {
    const MAGIC: &'static [u8] = &[0x7f, 0x45, 0x4c, 0x46];

    pub fn parse_or_print_error(i: parse::Input) -> Option<Self> {
        match Self::parse(i) {
            Ok((_, file)) => Some(file),
            Err(nom::Err::Failure(err)) | Err(nom::Err::Error(err)) => {
                eprintln!("Parsing failed:");
                for (input, err) in err.errors {
                    use nom::Offset;
                    let offset = i.offset(input);
                    eprintln!("{:?} at position {}:", err, offset);
                    eprintln!("{:>08x}: {:?}", offset, HexDump(input));
                }
                None
            }
            Err(_) => panic!("unexpected nom error"),
        }
    }

    #[allow(unused_variables)]
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        let full_input = i;
        use nom::{
            bytes::complete::{tag, take},
            combinator::verify,
            error::context,
            number::complete::le_u32,
            sequence::tuple,
        };
        let (i, _) = tuple((
            context("Magic", tag(Self::MAGIC)),
            context("Class", tag(&[0x2])),
            context("Endianness", tag(&[0x1])),
            context("Version", tag(&[0x1])),
            context("OS ABI", nom::branch::alt((tag(&[0x0]), tag(&[0x3])))),
            context("Padding", take(8_usize)),
        ))(i)?;

        let (i, (r#type, machine)) = tuple((Type::parse, Machine::parse))(i)?;
        let (i, _) = context("Version (bis)", verify(le_u32, |&x| x == 1))(i)?; // 校验 version
        let (i, entry_point) = Addr::parse(i)?; // entry_point

        use nom::{combinator::map, number::complete::le_u16};
        // some values are stored as u16 to save storage, but they're actually
        // file offsets, or counts, so we want them as `usize` in rust.
        let u16_usize = map(le_u16, |x| x as usize);

        // ph = program header, sh = section header
        let (i, (ph_offset, sh_offset)) = tuple((Addr::parse, Addr::parse))(i)?;
        let (i, (flags, hdr_size)) = tuple((le_u32, le_u16))(i)?;
        let (i, (ph_entsize, ph_count)) = tuple((&u16_usize, &u16_usize))(i)?;
        let (i, (sh_entsize, sh_count, sh_nidx)) = tuple((&u16_usize, &u16_usize, &u16_usize))(i)?;

        // `chunks()` divides a slice into chunks of equal size - perfect, as we know the entry size.
        let ph_slices = (&full_input[ph_offset.into()..]).chunks(ph_entsize);
        let mut program_headers = Vec::new();
        for ph_slice in ph_slices.take(ph_count) {
            let (_, ph) = ProgramHeader::parse(full_input, ph_slice)?;
            program_headers.push(ph);
        }

        let sh_slices = (&full_input[sh_offset.into()..]).chunks(sh_entsize);
        let mut section_headers = Vec::new();
        for sh_slice in sh_slices.take(sh_count) {
            let (_, sh) = SectionHeader::parse(sh_slice)?;
            section_headers.push(sh);
        }

        let res = Self {
            machine,
            r#type,
            entry_point,
            program_headers,
            section_headers,
        };
        Ok((i, res))
    }

    pub fn read_rela_entries(&self) -> Result<Vec<Rela>, ReadRelaError> {
        use DynamicTag as DT;
        use ReadRelaError as E;

        match self.dynamic_entry(DT::Rela) {
            None => Ok(vec![]),
            Some(addr) => {
                let len = self.get_dynamic_entry(DT::RelaSz)?;

                let i = self.slice_at(addr).ok_or(E::RelaSegmentNotFound)?;
                let i = &i[..len.into()];

                let n: usize = len.0 as usize / Rela::SIZE;
                match nom::multi::many_m_n(n, n, Rela::parse)(i) {
                    Ok((_, rela_entries)) => Ok(rela_entries),
                    Err(nom::Err::Failure(err)) | Err(nom::Err::Error(err)) => {
                        Err(E::ParsingError(format!("{:?}", err)))
                    }
                    _ => unreachable!(),
                }
            }
        }
    }

    pub fn segment_at(&self, addr: Addr) -> Option<&ProgramHeader> {
        self.program_headers
            .iter()
            .filter(|ph| ph.r#type == SegmentType::Load)
            .find(|ph| ph.mem_range().contains(&addr))
    }

    pub fn segment_of_type(&self, r#type: SegmentType) -> Option<&ProgramHeader> {
        self.program_headers.iter().find(|ph| ph.r#type == r#type)
    }

    pub fn dynamic_table(&self) -> Option<&[DynamicEntry]> {
        match self.segment_of_type(SegmentType::Dynamic) {
            Some(ProgramHeader {
                contents: SegmentContents::Dynamic(entries),
                ..
            }) => Some(entries),
            _ => None,
        }
    }

    pub fn dynamic_entries(&self, tag: DynamicTag) -> impl Iterator<Item = Addr> + '_ {
        self.dynamic_table()
            .unwrap_or_default()
            .iter()
            .filter(move |e| e.tag == tag)
            .map(|e| e.addr)
    }

    pub fn dynamic_entry_strings(&self, tag: DynamicTag) -> impl Iterator<Item = String> + '_ {
        self.dynamic_entries(tag)
            .filter_map(move |addr| self.get_string(addr).ok())
    }

    pub fn dynamic_entry(&self, tag: DynamicTag) -> Option<Addr> {
        self.dynamic_entries(tag).next()
    }

    pub fn slice_at(&self, mem_addr: Addr) -> Option<&[u8]> {
        self.segment_at(mem_addr)
            .map(|seg| &seg.data[(mem_addr - seg.mem_range().start).into()..])
    }

    pub fn get_string(&self, offset: Addr) -> Result<String, GetStringError> {
        use DynamicTag as DT;
        use GetStringError as E;

        let addr = self.dynamic_entry(DT::StrTab).ok_or(E::StrTabNotFound)?;
        let slice = self
            .slice_at(addr + offset)
            .ok_or(E::StrTabSegmentNotFound)?;
        let string_slice = slice.split(|&c| c == 0).next().ok_or(E::StringNotFound)?;
        Ok(String::from_utf8_lossy(string_slice).into())
    }

    pub fn section_starting_at(&self, addr: Addr) -> Option<&SectionHeader> {
        self.section_headers.iter().find(|sh| sh.addr == addr)
    }

    pub fn read_syms(&self) -> Result<Vec<Sym>, ReadSymsError> {
        use DynamicTag as DT;
        use ReadSymsError as E;

        let addr = self.get_dynamic_entry(DT::SymTab)?;
        let section = self
            .section_starting_at(addr)
            .ok_or(E::SymTabSectionNotFound)?;

        let i = self.slice_at(addr).ok_or(E::SymTabSegmentNotFound)?;
        let n = (section.size.0 / section.entsize.0) as usize;
        use nom::multi::many_m_n;

        match many_m_n(n, n, Sym::parse)(i) {
            Ok((_, syms)) => Ok(syms),
            Err(nom::Err::Failure(err)) | Err(nom::Err::Error(err)) => {
                Err(E::ParsingError(format!("{:?}", err)))
            }
            _ => unreachable!(),
        }
    }

    pub fn get_dynamic_entry(&self, tag: DynamicTag) -> Result<Addr, GetDynamicEntryError> {
        self.dynamic_entry(tag)
            .ok_or(GetDynamicEntryError::NotFound(tag))
    }
}

#[cfg(test)]
mod tests {
    use super::Machine;
    use std::convert::TryFrom;

    #[test]
    fn type_to_u16() {
        assert_eq!(super::Type::Dyn as u16, 0x3);
    }

    #[test]
    fn type_from_u16() {
        assert_eq!(super::Type::try_from(0x3), Ok(super::Type::Dyn));
        assert_eq!(super::Type::try_from(0xf00d), Err(0xf00d));
    }

    #[test]
    fn try_enums() {
        assert_eq!(Machine::X86_64 as u16, 0x3E);
        assert_eq!(Machine::try_from(0x3E), Ok(Machine::X86_64));
        assert_eq!(Machine::try_from(0xFA), Err(0xFA));
    }

    #[test]
    fn try_bitflag() {
        use super::SegmentFlag;
        use enumflags2::BitFlags;

        // this is a value we could've read straight from an ELF file
        let flags_integer: u32 = 6;
        // this is how we parse it. in practice, it's less verbose,
        // because of type inference.
        let flags = BitFlags::<SegmentFlag>::from_bits(flags_integer).unwrap();
        assert_eq!(flags, SegmentFlag::Read | SegmentFlag::Write);
        assert_eq!(flags.bits(), flags_integer);

        // this does not correspond to any flags
        assert!(BitFlags::<SegmentFlag>::from_bits(1992).is_err());
    }
}
